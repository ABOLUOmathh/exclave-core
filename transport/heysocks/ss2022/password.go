// Package ss2022 implements the opt-in BLACKSTONE/HeySocks extensions to
// Shadowsocks 2022. The standard Shadowsocks 2022 implementation is untouched.
package ss2022

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	MethodAES128GCM  = "2022-blake3-aes-128-gcm"
	BlackstoneSuffix = "#BLACKSTONE"
)

// NormalizePassword preserves all standard passwords. A trailing BLACKSTONE
// marker enables the custom protocol only for the AES-128-GCM 2022 method.
// The normalized secret must not be logged or displayed in an error message.
func NormalizePassword(method, password string) (normalized string, blackstone bool, err error) {
	if !strings.HasSuffix(password, BlackstoneSuffix) {
		return password, false, nil
	}
	if method != MethodAES128GCM {
		return "", false, fmt.Errorf("heysocks ss2022: BLACKSTONE marker requires %s", MethodAES128GCM)
	}
	normalized = strings.TrimSuffix(password, BlackstoneSuffix)
	if normalized == "" {
		return "", false, fmt.Errorf("heysocks ss2022: empty password before BLACKSTONE marker")
	}
	return normalized, true, nil
}

// ParseKeys validates the identity-PSK/master-PSK sequence required by the
// Mihomo custom method. In BLACKSTONE mode every key is strict Base64 of 16
// bytes; the last is the master key and all preceding keys are identity PSKs.
func ParseKeys(normalized string) (identityPSKs [][]byte, masterPSK []byte, err error) {
	parts := strings.Split(normalized, ":")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("heysocks ss2022: expected identityPSK:masterPSK")
	}
	keys := make([][]byte, 0, len(parts))
	for i, part := range parts {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil {
			return nil, nil, fmt.Errorf("heysocks ss2022: invalid Base64 in password component %d: %w", i, err)
		}
		if len(key) != 16 {
			return nil, nil, fmt.Errorf("heysocks ss2022: password component %d decoded to %d bytes, expected 16", i, len(key))
		}
		keys = append(keys, key)
	}
	return keys[:len(keys)-1], keys[len(keys)-1], nil
}
