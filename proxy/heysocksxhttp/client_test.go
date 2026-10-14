package heysocksxhttp

import (
	"bytes"
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/net/uot"
)

func TestMemoryAccountKeepsPeerSession(t *testing.T) {
	account := &MemoryAccount{CipherName: "aes-128-ctr", Password: "test-key:02aabb"}
	first, err := account.NewCipher()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SetSessionBlob([]byte{1, 0x42}); err != nil {
		t.Fatal(err)
	}
	second, err := account.NewCipher()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("session cipher recreated instead of reused")
	}
	if !bytes.Equal(second.SessionBlob(), []byte{1, 0x42}) {
		t.Fatal("updated session was not reused")
	}
}

func TestUOTVersionSelection(t *testing.T) {
	for _, tc := range []struct {
		version uint32
		magic   string
	}{
		{0, uot.MagicAddressV2},
		{1, uot.MagicAddressV1},
		{2, uot.MagicAddressV2},
	} {
		target, err := uotMagicTarget(tc.version)
		if err != nil {
			t.Fatal(err)
		}
		if target.Address.String() != tc.magic {
			t.Fatalf("version %d: got %s, want %s", tc.version, target.Address, tc.magic)
		}
	}
	if _, err := uotMagicTarget(3); err == nil {
		t.Fatal("unsupported UOT version accepted")
	}
}
