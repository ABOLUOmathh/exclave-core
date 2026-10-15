package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing/common/uot"

	coreNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/transport/heysocks/ss2022"
)

// This suite deliberately tests the existing NewClient path, not just the
// new transport package. Unmarked SS2022 must keep its original cipher and
// UOT behavior when BLACKSTONE is added as an opt-in extension.
func TestStandardAndBlackstoneConfigurationIsolation(t *testing.T) {
	psk16 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	master16 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 16))
	psk32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	master32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	standard128 := psk16 + ":" + master16
	standard256 := psk32 + ":" + master32

	cases := []struct {
		name, method, password string
		uot, custom, wantError bool
		wantUOTVersion         uint8
	}{
		{name: "standard AES-128 TCP", method: ss2022.MethodAES128GCM, password: standard128},
		{name: "standard AES-128 UOT unchanged", method: ss2022.MethodAES128GCM, password: standard128, uot: true},
		{name: "standard AES-256 TCP", method: "2022-blake3-aes-256-gcm", password: standard256},
		{name: "standard ChaCha20 TCP", method: "2022-blake3-chacha20-poly1305", password: psk32},
		{name: "BLACKSTONE TCP", method: ss2022.MethodAES128GCM, password: standard128 + ss2022.BlackstoneSuffix, custom: true},
		{name: "BLACKSTONE Legacy UOT v1", method: ss2022.MethodAES128GCM, password: standard128 + ss2022.BlackstoneSuffix, custom: true, uot: true, wantUOTVersion: uot.LegacyVersion},
		{name: "BLACKSTONE rejects unsupported cipher", method: "2022-blake3-aes-256-gcm", password: standard256 + ss2022.BlackstoneSuffix, wantError: true},
		{name: "BLACKSTONE rejects missing identity PSK", method: ss2022.MethodAES128GCM, password: master16 + ss2022.BlackstoneSuffix, wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ClientConfig{
				Address: coreNet.NewIPOrDomain(coreNet.DomainAddress("localhost")),
				Port:    8388,
				Method:  tc.method,
				Key:     tc.password,
				Uot:     tc.uot,
			}
			client, err := NewClient(context.Background(), config)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected configuration to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClient failed: %v", err)
			}
			defer client.Close()

			if tc.custom {
				if client.blackstone == nil || client.method != nil {
					t.Fatal("BLACKSTONE node did not select isolated custom method")
				}
			} else if client.blackstone != nil || client.method == nil {
				t.Fatal("unmarked SS2022 node no longer selects standard method")
			}

			if tc.uot {
				if client.uotClient == nil {
					t.Fatal("UOT unexpectedly disabled")
				}
				if client.uotClient.Version != tc.wantUOTVersion {
					t.Fatalf("UOT version = %d, want %d", client.uotClient.Version, tc.wantUOTVersion)
				}
			} else if client.uotClient != nil {
				t.Fatal("UOT unexpectedly enabled")
			}
		})
	}
}

func TestBLACKSTONELegacyUOTDestination(t *testing.T) {
	dest := uot.RequestDestination(uot.LegacyVersion)
	if dest.Fqdn != uot.LegacyMagicAddress {
		t.Fatalf("Legacy UOT address = %q, want %q", dest.Fqdn, uot.LegacyMagicAddress)
	}
	// Protect original UOT v2 magic address used by all pre-existing nodes.
	originalDest := uot.RequestDestination(0)
	if originalDest.Fqdn != uot.MagicAddress {
		t.Fatalf("standard UOT destination = %q, want %q", originalDest.Fqdn, uot.MagicAddress)
	}
}
