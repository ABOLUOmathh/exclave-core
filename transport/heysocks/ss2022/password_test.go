package ss2022

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func examplePassword() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)) + ":" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
}

func TestNormalizePassword(t *testing.T) {
	valid := examplePassword()
	cases := []struct {
		name, method, password, want string
		custom, wantError            bool
	}{
		{name: "standard preserved", method: MethodAES128GCM, password: valid, want: valid},
		{name: "custom detected", method: MethodAES128GCM, password: valid + BlackstoneSuffix, want: valid, custom: true},
		{name: "standard different cipher preserved", method: "2022-blake3-aes-256-gcm", password: valid, want: valid},
		{name: "invalid custom cipher", method: "2022-blake3-aes-256-gcm", password: valid + BlackstoneSuffix, wantError: true},
		{name: "empty custom password", method: MethodAES128GCM, password: BlackstoneSuffix, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, custom, err := NormalizePassword(tc.method, tc.password)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, expected error = %v", err, tc.wantError)
			}
			if tc.wantError {
				return
			}
			if got != tc.want || custom != tc.custom {
				t.Fatalf("normalized mismatch or custom flag: custom=%v", custom)
			}
		})
	}
}

func TestParseKeys(t *testing.T) {
	identity, master, err := ParseKeys(examplePassword())
	if err != nil {
		t.Fatal(err)
	}
	if len(identity) != 1 || !bytes.Equal(identity[0], bytes.Repeat([]byte{1}, 16)) ||
		!bytes.Equal(master, bytes.Repeat([]byte{2}, 16)) {
		t.Fatal("identity/master split incorrect")
	}

	for _, bad := range []string{
		"only-one-key", // insufficient components
		examplePassword() + ":not!base64",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 15)) + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16)),
		strings.TrimSuffix(examplePassword(), "=") + "A", // malformed trailing padding
	} {
		if _, _, err := ParseKeys(bad); err == nil {
			t.Fatal("accepted malformed key material")
		}
	}
}
