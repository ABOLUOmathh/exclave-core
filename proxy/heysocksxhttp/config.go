package heysocksxhttp

import (
	"strings"

	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/xhttp"
)

const DefaultCipher = "aes-128-ctr"

// MemoryAccount is a runtime Exclave account; its wire cipher is recreated per
// connection because HeySocks synchronizes session state on received frames.
type MemoryAccount struct {
	CipherName string
	Password   string
	FakeTCP    string
	FakeUDP    string
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.Password == b.Password &&
		strings.EqualFold(a.CipherName, b.CipherName) &&
		a.FakeTCP == b.FakeTCP && a.FakeUDP == b.FakeUDP
}

func (a *MemoryAccount) NewCipher() (*wire.StreamCipher, error) {
	return wire.NewStreamCipher(a.CipherName, a.Password, map[string]string{
		"tcp": a.FakeTCP,
		"udp": a.FakeUDP,
	})
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
