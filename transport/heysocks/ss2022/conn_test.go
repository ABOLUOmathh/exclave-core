package ss2022

import (
	"bytes"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type captureConn struct {
	net.Conn
	sent bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.sent.Write(p) }

// Exclave may send an empty first-flight trigger when the inbound client has
// not yet provided application bytes. The custom transport must still send a
// complete BLACKSTONE request instead of hanging until a non-empty write.
func TestEmptyWriteTriggersFirstFlight(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	capture := &captureConn{}
	conn := method.DialEarlyConn(capture, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	n, err := conn.Write(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty write returned %d bytes", n)
	}
	if capture.sent.Len() < 16+identityHeaderLength+tcpRequestFixedPlainLength+16 {
		t.Fatalf("first flight not sent: only %d bytes", capture.sent.Len())
	}
	firstLen := capture.sent.Len()
	if _, err := conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	if capture.sent.Len() != firstLen {
		t.Fatal("empty write retransmitted first flight")
	}
	payload := []byte("after-first-flight")
	n, err = conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d of %d", n, len(payload))
	}
	if capture.sent.Len() <= firstLen {
		t.Fatal("payload was not streamed")
	}
}
