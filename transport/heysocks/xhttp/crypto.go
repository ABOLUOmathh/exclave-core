package xhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

const CipherAES128CTR = "AES-128-CTR"
const identitySuffix = "do not hack this protocol please"

// StreamCipher holds the parameters needed to exchange the HeySocks XHTTP
// wire format. AES-CTR and MD5 are protocol requirements, not new crypto choices.
type StreamCipher struct {
	key      []byte
	identity [md5.Size]byte
	fakeNet  map[string][]byte

	mu      sync.RWMutex
	session []byte
}

// KDF expands successive MD5 digests, with each round fed the preceding
// digest and the original password, to the requested number of bytes.
func KDF(password string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("xhttp: invalid key length %d", keyLen)
	}
	key := make([]byte, 0, keyLen)
	var prev []byte
	for len(key) < keyLen {
		hash := md5.New() // Required by the existing protocol.
		if len(prev) > 0 {
			_, _ = hash.Write(prev)
		}
		_, _ = hash.Write([]byte(password))
		prev = hash.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen], nil
}

// NewStreamCipher expects the credential form key:hex-session-blob. fakeNet
// contains optional hex strings indexed by "tcp" or "udp".
func NewStreamCipher(method, password string, fakeNet map[string]string) (*StreamCipher, error) {
	if !strings.EqualFold(method, CipherAES128CTR) {
		return nil, fmt.Errorf("xhttp: unsupported cipher %q", method)
	}
	parts := strings.Split(password, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("xhttp: password must be key:hex-session-blob")
	}
	key, err := KDF(parts[0], aes.BlockSize)
	if err != nil {
		return nil, err
	}
	session, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("xhttp: invalid session hex: %w", err)
	}
	if err := validateSessionBlob(session); err != nil {
		return nil, err
	}
	fake := make(map[string][]byte, len(fakeNet))
	for network, value := range fakeNet {
		if value == "" {
			continue
		}
		bytes, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("xhttp: invalid fake-%s hex: %w", network, err)
		}
		if len(bytes) > fakePrefixSize {
			return nil, fmt.Errorf("xhttp: fake-%s longer than %d bytes", network, fakePrefixSize)
		}
		fake[network] = bytes
	}
	return &StreamCipher{
		key:      key,
		identity: md5.Sum([]byte(parts[0] + identitySuffix)), // Existing wire identity.
		session:  append([]byte(nil), session...),
		fakeNet:  fake,
	}, nil
}

func (c *StreamCipher) IVSize() int              { return aes.BlockSize }
func (c *StreamCipher) Identity() [md5.Size]byte { return c.identity }
func (c *StreamCipher) FakeNet(network string) []byte {
	return append([]byte(nil), c.fakeNet[network]...)
}
func (c *StreamCipher) SessionBlob() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.session...)
}
func (c *StreamCipher) SetSessionBlob(blob []byte) error {
	if err := validateSessionBlob(blob); err != nil {
		return err
	}
	c.mu.Lock()
	c.session = append([]byte(nil), blob...)
	c.mu.Unlock()
	return nil
}
func (c *StreamCipher) Encrypter(iv []byte) (cipher.Stream, error) { return c.newCTR(iv) }
func (c *StreamCipher) Decrypter(iv []byte) (cipher.Stream, error) { return c.newCTR(iv) }
func (c *StreamCipher) newCTR(iv []byte) (cipher.Stream, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("xhttp: invalid IV size %d", len(iv))
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func validateSessionBlob(blob []byte) error {
	if len(blob) == 0 {
		return fmt.Errorf("xhttp: empty session")
	}
	if int(blob[0]) != len(blob)-1 {
		return fmt.Errorf("xhttp: session length mismatch: %d != %d", blob[0], len(blob)-1)
	}
	return nil
}
