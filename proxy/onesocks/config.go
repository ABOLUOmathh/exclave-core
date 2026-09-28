package onesocks

import (
	"strings"

	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
)

const DefaultCipher = "aes-128-ctr"

// MemoryAccount is the runtime form of an OneSocks account.
type MemoryAccount struct {
	Cipher     *wire.StreamCipher
	CipherName string
	Password   string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	account, ok := another.(*MemoryAccount)
	if !ok {
		return false
	}

	return a.Password == account.Password &&
		strings.EqualFold(a.CipherName, account.CipherName)
}

// AsAccount converts the protobuf account into its runtime representation.
func (a *Account) AsAccount() (protocol.Account, error) {
	cipherName := a.Cipher
	if cipherName == "" {
		cipherName = DefaultCipher
	}

	streamCipher, err := wire.NewStreamCipher(
		cipherName,
		a.Password,
	)
	if err != nil {
		return nil, err
	}

	return &MemoryAccount{
		Cipher:     streamCipher,
		CipherName: cipherName,
		Password:   a.Password,
	}, nil
}
