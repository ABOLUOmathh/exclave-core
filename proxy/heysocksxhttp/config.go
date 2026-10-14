package heysocksxhttp

import (
	"strings"
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/xhttp"
)

const DefaultCipher = "aes-128-ctr"

// MemoryAccount keeps a single stream cipher per server account. The cipher
// synchronizes session blobs received from the peer, so sharing it across
// connections preserves the current session, as in the HeySocks implementation.
type MemoryAccount struct {
	CipherName string
	Password   string
	FakeTCP    string
	FakeUDP    string

	cipherOnce sync.Once
	cipher     *wire.StreamCipher
	cipherErr  error
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.Password == b.Password &&
		strings.EqualFold(a.CipherName, b.CipherName) &&
		a.FakeTCP == b.FakeTCP && a.FakeUDP == b.FakeUDP
}

func (a *MemoryAccount) NewCipher() (*wire.StreamCipher, error) {
	a.cipherOnce.Do(func() {
		a.cipher, a.cipherErr = wire.NewStreamCipher(a.CipherName, a.Password, map[string]string{
			"tcp": a.FakeTCP,
			"udp": a.FakeUDP,
		})
	})
	return a.cipher, a.cipherErr
}

func (a *Account) AsAccount() (protocol.Account, error) {
	cipherName := a.Cipher
	if cipherName == "" {
		cipherName = DefaultCipher
	}
	account := &MemoryAccount{
		CipherName: cipherName,
		Password:   a.Password,
		FakeTCP:    a.FakeTcp,
		FakeUDP:    a.FakeUdp,
	}
	if _, err := account.NewCipher(); err != nil {
		return nil, err
	}
	return account, nil
}
