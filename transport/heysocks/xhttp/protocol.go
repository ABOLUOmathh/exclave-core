package xhttp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	fakePrefixSize = 128
	identitySize   = 16
)

// createBootstrap constructs the native HeySocks XHTTP first-flight header:
// [128-byte fake/random prefix][16-byte identity][session length+data][IV size][IV].
func createBootstrap(c *StreamCipher, network string, random io.Reader) ([]byte, []byte, error) {
	if random == nil {
		random = rand.Reader
	}
	session := c.SessionBlob()
	if err := validateSessionBlob(session); err != nil {
		return nil, nil, err
	}
	fake := c.FakeNet(network)
	if len(fake) > fakePrefixSize {
		return nil, nil, fmt.Errorf("xhttp: oversized fake prefix")
	}

	header := make([]byte, fakePrefixSize+identitySize+len(session)+1+c.IVSize())
	copy(header, fake)
	if _, err := io.ReadFull(random, header[len(fake):fakePrefixSize]); err != nil {
		return nil, nil, fmt.Errorf("xhttp: random prefix: %w", err)
	}
	offset := fakePrefixSize
	identity := c.Identity()
	copy(header[offset:], identity[:])
	offset += identitySize
	copy(header[offset:], session)
	offset += len(session)
	header[offset] = byte(c.IVSize())
	offset++
	iv := header[offset:]
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, nil, fmt.Errorf("xhttp: random IV: %w", err)
	}
	return header, append([]byte(nil), iv...), nil
}

func readBootstrap(r io.Reader, c *StreamCipher) ([]byte, error) {
	prefix := make([]byte, fakePrefixSize+identitySize)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("xhttp: read prefix/identity: %w", err)
	}
	identity := c.Identity()
	if !bytes.Equal(prefix[fakePrefixSize:], identity[:]) {
		return nil, fmt.Errorf("xhttp: identity mismatch")
	}

	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("xhttp: read session size: %w", err)
	}
	blob := make([]byte, int(n[0])+1)
	blob[0] = n[0]
	if _, err := io.ReadFull(r, blob[1:]); err != nil {
		return nil, fmt.Errorf("xhttp: read session: %w", err)
	}
	if err := c.SetSessionBlob(blob); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("xhttp: read IV size: %w", err)
	}
	iv := make([]byte, int(n[0]))
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf("xhttp: read IV: %w", err)
	}
	return iv, nil
}

// PackPacket encrypts one UDP datagram using an independent IV and bootstrap.
func PackPacket(c *StreamCipher, plaintext []byte, random io.Reader) ([]byte, error) {
	header, iv, err := createBootstrap(c, "udp", random)
	if err != nil {
		return nil, err
	}
	cipherStream, err := c.Encrypter(iv)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, len(header)+len(plaintext))
	copy(packet, header)
	cipherStream.XORKeyStream(packet[len(header):], plaintext)
	return packet, nil
}

// UnpackPacket validates the identity, updates session state and decrypts UDP.
func UnpackPacket(c *StreamCipher, packet []byte) ([]byte, error) {
	minLen := fakePrefixSize + identitySize + 1 + 1
	if len(packet) < minLen {
		return nil, fmt.Errorf("xhttp: truncated UDP bootstrap")
	}
	identity := c.Identity()
	if !bytes.Equal(packet[fakePrefixSize:fakePrefixSize+identitySize], identity[:]) {
		return nil, fmt.Errorf("xhttp: identity mismatch")
	}
	offset := fakePrefixSize + identitySize
	n := int(packet[offset])
	offset++
	if len(packet) < offset+n+1 {
		return nil, fmt.Errorf("xhttp: truncated session")
	}
	session := make([]byte, n+1)
	session[0] = byte(n)
	copy(session[1:], packet[offset:offset+n])
	offset += n
	if err := c.SetSessionBlob(session); err != nil {
		return nil, err
	}
	ivSize := int(packet[offset])
	offset++
	if len(packet) < offset+ivSize {
		return nil, fmt.Errorf("xhttp: truncated IV")
	}
	cipherStream, err := c.Decrypter(packet[offset : offset+ivSize])
	if err != nil {
		return nil, err
	}
	offset += ivSize
	plaintext := make([]byte, len(packet)-offset)
	cipherStream.XORKeyStream(plaintext, packet[offset:])
	return plaintext, nil
}
