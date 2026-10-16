package encoding_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/proxy/vless"
	"github.com/exclavenetwork/exclave-core/v5/proxy/vless/encoding"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}

func testRequestHeader(e bool, hHex string) (*protocol.RequestHeader, *encoding.Addons) {
	accProto := &vless.Account{
		Id:   "00112233-4455-6677-8899-aabbccddeeff",
		Flow: "",
		E:    e,
		H:    hHex,
	}
	memAcc, _ := accProto.AsAccount()

	user := &protocol.MemoryUser{
		Account: memAcc,
	}

	request := &protocol.RequestHeader{
		Version: 0,
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: net.LocalHostIP,
		Port:    net.Port(443),
	}

	addons := &encoding.Addons{}
	return request, addons
}

func TestEncodeRequestHeaderLegacy(t *testing.T) {
	req, addons := testRequestHeader(false, "")
	var b bytes.Buffer
	if err := encoding.EncodeRequestHeader(&b, req, addons); err != nil {
		t.Fatalf("EncodeRequestHeader: %v", err)
	}

	// Legacy length: 1(ver) + 16(uuid) + 1(addons len) + 1(cmd) + 1(addr type) + 4(ip) + 2(port) = 26 bytes
	if b.Len() != 26 {
		t.Fatalf("expected legacy header length 26, got %d", b.Len())
	}
}

func TestEncodeRequestHeaderEOnly(t *testing.T) {
	reqLegacy, addonsLegacy := testRequestHeader(false, "")
	var bLegacy bytes.Buffer
	_ = encoding.EncodeRequestHeader(&bLegacy, reqLegacy, addonsLegacy)

	req, addons := testRequestHeader(true, "")
	var b bytes.Buffer
	if err := encoding.EncodeRequestHeader(&b, req, addons); err != nil {
		t.Fatalf("EncodeRequestHeader: %v", err)
	}

	expectedLen := bLegacy.Len() + md5.Size
	if b.Len() != expectedLen {
		t.Fatalf("expected length %d, got %d", expectedLen, b.Len())
	}

	memAcc := req.User.Account.(*vless.MemoryAccount)
	wantMD5 := md5.Sum(memAcc.ID.Bytes())

	gotMD5 := b.Bytes()[bLegacy.Len():]
	if !bytes.Equal(gotMD5, wantMD5[:]) {
		t.Fatalf("MD5 mismatch: got %x, want %x", gotMD5, wantMD5[:])
	}
}

func TestEncodeRequestHeaderHOnly(t *testing.T) {
	const hHex = "03aabbcc"
	reqLegacy, addonsLegacy := testRequestHeader(false, "")
	var bLegacy bytes.Buffer
	_ = encoding.EncodeRequestHeader(&bLegacy, reqLegacy, addonsLegacy)

	req, addons := testRequestHeader(false, hHex)
	var b bytes.Buffer
	if err := encoding.EncodeRequestHeader(&b, req, addons); err != nil {
		t.Fatalf("EncodeRequestHeader: %v", err)
	}

	hBytes := mustHex(t, hHex)
	expectedLen := bLegacy.Len() + len(hBytes)
	if b.Len() != expectedLen {
		t.Fatalf("expected length %d, got %d", expectedLen, b.Len())
	}

	gotH := b.Bytes()[bLegacy.Len():]
	if !bytes.Equal(gotH, hBytes) {
		t.Fatalf("H mismatch: got %x, want %x", gotH, hBytes)
	}
}

func TestEncodeRequestHeaderEAndH(t *testing.T) {
	const hHex = "03aabbcc"
	reqLegacy, addonsLegacy := testRequestHeader(false, "")
	var bLegacy bytes.Buffer
	_ = encoding.EncodeRequestHeader(&bLegacy, reqLegacy, addonsLegacy)

	req, addons := testRequestHeader(true, hHex)
	var b bytes.Buffer
	if err := encoding.EncodeRequestHeader(&b, req, addons); err != nil {
		t.Fatalf("EncodeRequestHeader: %v", err)
	}

	memAcc := req.User.Account.(*vless.MemoryAccount)
	wantMD5 := md5.Sum(memAcc.ID.Bytes())
	hBytes := mustHex(t, hHex)

	expectedLen := bLegacy.Len() + md5.Size + len(hBytes)
	if b.Len() != expectedLen {
		t.Fatalf("expected length %d, got %d", expectedLen, b.Len())
	}

	gotMD5 := b.Bytes()[bLegacy.Len() : bLegacy.Len()+md5.Size]
	gotH := b.Bytes()[bLegacy.Len()+md5.Size:]

	if !bytes.Equal(gotMD5, wantMD5[:]) {
		t.Fatalf("MD5 mismatch: got %x, want %x", gotMD5, wantMD5[:])
	}
	if !bytes.Equal(gotH, hBytes) {
		t.Fatalf("H mismatch: got %x, want %x", gotH, hBytes)
	}
}

func TestDecodeResponseHeaderUpdatesH(t *testing.T) {
	const hHex = "03aabbcc"
	req, _ := testRequestHeader(true, hHex)
	memAcc := req.User.Account.(*vless.MemoryAccount)

	// Response buffer: Version=0, AddonsLen=0, hLen=2, newH={0xde, 0xad}
	respData := []byte{
		0x00,       // version
		0x00,       // addons length
		0x02,       // hLen
		0xde, 0xad, // new H data
	}

	reader := bytes.NewReader(respData)
	_, err := encoding.DecodeResponseHeader(reader, req)
	if err != nil {
		t.Fatalf("DecodeResponseHeader: %v", err)
	}

	_, updatedH := memAcc.HeySocksSnapshot()
	wantH := []byte{0x02, 0xde, 0xad}
	if !bytes.Equal(updatedH, wantH) {
		t.Fatalf("updated H mismatch: got %x, want %x", updatedH, wantH)
	}
}

func TestDecodeResponseHeaderZeroLengthPreservesH(t *testing.T) {
	const hHex = "03aabbcc"
	req, _ := testRequestHeader(true, hHex)
	memAcc := req.User.Account.(*vless.MemoryAccount)

	// Response buffer: Version=0, AddonsLen=0, hLen=0 (preserves existing H)
	respData := []byte{
		0x00, // version
		0x00, // addons length
		0x00, // hLen
	}

	reader := bytes.NewReader(respData)
	_, err := encoding.DecodeResponseHeader(reader, req)
	if err != nil {
		t.Fatalf("DecodeResponseHeader: %v", err)
	}

	_, preservedH := memAcc.HeySocksSnapshot()
	wantH := mustHex(t, hHex)
	if !bytes.Equal(preservedH, wantH) {
		t.Fatalf("preserved H mismatch: got %x, want %x", preservedH, wantH)
	}
}
