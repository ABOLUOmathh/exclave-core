package xhttp

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

func testCipher(t *testing.T) *StreamCipher {
	t.Helper()
	c, err := NewStreamCipher("aes-128-ctr", "passkey:03aabbcc", map[string]string{"tcp": "010203", "udp": "c0ffee"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBootstrapWireFields(t *testing.T) {
	c := testCipher(t)
	header, iv, err := createBootstrap(c, "tcp", bytes.NewReader(bytes.Repeat([]byte{0x4a}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 128+16+4+1+aes.BlockSize {
		t.Fatalf("length %d", len(header))
	}
	if !bytes.Equal(header[:3], []byte{1, 2, 3}) {
		t.Fatal("fake TCP prefix")
	}
	if !bytes.Equal(header[3:128], bytes.Repeat([]byte{0x4a}, 125)) {
		t.Fatal("fake padding")
	}
	identity := md5.Sum([]byte("passkeydo not hack this protocol please"))
	if !bytes.Equal(header[128:144], identity[:]) {
		t.Fatal("identity bytes")
	}
	if !bytes.Equal(header[144:148], []byte{3, 0xaa, 0xbb, 0xcc}) {
		t.Fatal("session")
	}
	if header[148] != aes.BlockSize || !bytes.Equal(iv, header[149:]) {
		t.Fatal("IV")
	}
	receiver := testCipher(t)
	parsedIV, err := readBootstrap(bytes.NewReader(header), receiver)
	if err != nil || !bytes.Equal(iv, parsedIV) {
		t.Fatalf("read bootstrap: %v", err)
	}
}

func TestDatagramWireRoundtrip(t *testing.T) {
	c := testCipher(t)
	plaintext := []byte{3, 4, 'h', 'o', 's', 't', 0x01, 0xbb, 'u', 'd', 'p'}
	wire, err := PackPacket(c, plaintext, bytes.NewReader(bytes.Repeat([]byte{0x58}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(wire[:3]) != "c0ffee" {
		t.Fatal("UDP fake prefix")
	}
	got, err := UnpackPacket(testCipher(t), wire)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("unpack: %q, %v", got, err)
	}
	wire[128] ^= 1
	if _, err := UnpackPacket(testCipher(t), wire); err == nil {
		t.Fatal("identity mismatch should fail")
	}
}

func TestEncryptedStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	dest := []byte{1, 127, 0, 0, 1, 0, 80}
	go func() {
		remote := testCipher(t)
		iv, err := readBootstrap(server, remote)
		if err != nil {
			done <- err
			return
		}
		dec, err := remote.Decrypter(iv)
		if err != nil {
			done <- err
			return
		}
		got := make([]byte, len(dest)+4)
		if _, err := io.ReadFull(server, got); err != nil {
			done <- err
			return
		}
		dec.XORKeyStream(got, got)
		if !bytes.Equal(got, append(append([]byte(nil), dest...), []byte("PING")...)) {
			done <- io.ErrUnexpectedEOF
			return
		}
		header, iv, err := createBootstrap(remote, "tcp", bytes.NewReader(bytes.Repeat([]byte{0x65}, 512)))
		if err != nil {
			done <- err
			return
		}
		enc, err := remote.Encrypter(iv)
		if err != nil {
			done <- err
			return
		}
		payload := []byte("PONG")
		enc.XORKeyStream(payload, payload)
		if err := writeAll(server, append(header, payload...)); err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	stream := NewConn(client, testCipher(t), dest)
	if _, err := stream.Write(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "PONG" {
		t.Fatalf("unexpected %q", reply)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMalformedSession(t *testing.T) {
	if _, err := NewStreamCipher("aes-128-ctr", "pass:02aa", nil); err == nil {
		t.Fatal("bad session accepted")
	}
	if _, err := NewStreamCipher("aes-256-ctr", "pass:00", nil); err == nil {
		t.Fatal("bad cipher accepted")
	}
	if _, err := NewStreamCipher("aes-128-ctr", "pass:00", map[string]string{"udp": "xy"}); err == nil {
		t.Fatal("bad fake-net accepted")
	}
}
