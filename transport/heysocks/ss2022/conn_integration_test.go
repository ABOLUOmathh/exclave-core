package ss2022

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

// blackstoneTestRequest is decrypted independently from the clientConn read path.
// Tests operate over net.Pipe, so partial reads/writes and first-flight framing
// cannot be accidentally hidden by a mocked net.Conn that merely captures bytes.
type blackstoneTestRequest struct {
	salt           []byte
	destination    M.Socksaddr
	initialPayload []byte
	stream         *streamCipher
}

func decodeBlackstoneTestRequest(conn net.Conn, method *Method) (*blackstoneTestRequest, error) {
	salt := make([]byte, len(method.psk))
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, err
	}
	for i := range method.identityPSKs {
		sealed := make([]byte, identityHeaderLength)
		if _, err := io.ReadFull(conn, sealed); err != nil {
			return nil, err
		}
		block, err := newAES(method.identityPSKs[i], salt, subkeyCtxIdentity)
		if err != nil {
			return nil, err
		}
		got := make([]byte, identityHeaderLength)
		block.Decrypt(got, sealed)
		if !bytes.Equal(got, method.eihPSKHashes[i][:]) {
			return nil, fmt.Errorf("EIH %d mismatch", i)
		}
	}

	reader, err := newSessionCipher(method.psk, salt)
	if err != nil {
		return nil, err
	}
	fixedSealed := make([]byte, tcpRequestFixedPlainLength+reader.overhead())
	if _, err := io.ReadFull(conn, fixedSealed); err != nil {
		return nil, err
	}
	fixed, err := reader.open(fixedSealed)
	if err != nil {
		return nil, err
	}
	if fixed[0] != headerTypeClientStream {
		return nil, fmt.Errorf("wrong request header type")
	}
	// The HeySocks E extension is covered separately by TestBuildFirstFlightContainsHeySocksEExtension.
	variableLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	variableSealed := make([]byte, variableLen+reader.overhead())
	if _, err := io.ReadFull(conn, variableSealed); err != nil {
		return nil, err
	}
	variable, err := reader.open(variableSealed)
	if err != nil {
		return nil, err
	}

	source := bytes.NewReader(variable)
	dest, err := M.SocksaddrSerializer.ReadAddrPort(source)
	if err != nil {
		return nil, err
	}
	var padding uint16
	if err := binary.Read(source, binary.BigEndian, &padding); err != nil {
		return nil, err
	}
	if int(padding) > source.Len() {
		return nil, fmt.Errorf("padding exceeds request length")
	}
	if _, err := io.CopyN(io.Discard, source, int64(padding)); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(source)
	if err != nil {
		return nil, err
	}
	return &blackstoneTestRequest{salt: salt, destination: dest, initialPayload: payload, stream: reader}, nil
}

func readBlackstoneTestFrame(conn net.Conn, stream *streamCipher) ([]byte, error) {
	sealedLength := make([]byte, 2+stream.overhead())
	if _, err := io.ReadFull(conn, sealedLength); err != nil {
		return nil, err
	}
	lengthPlain, err := stream.open(sealedLength)
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	if length == 0 {
		return nil, fmt.Errorf("zero-length frame")
	}
	sealedData := make([]byte, length+stream.overhead())
	if _, err := io.ReadFull(conn, sealedData); err != nil {
		return nil, err
	}
	return stream.open(sealedData)
}

func sendBlackstoneTestResponse(conn net.Conn, method *Method, requestSalt []byte, initial, subsequent []byte, corruptSalt bool) error {
	responseSalt := bytes.Repeat([]byte{0x73}, len(method.psk))
	stream, err := newSessionCipher(method.psk, responseSalt)
	if err != nil {
		return err
	}
	header := make([]byte, 1+8+len(requestSalt)+2)
	header[0] = headerTypeServerStream
	binary.BigEndian.PutUint64(header[1:], uint64(time.Now().Unix()))
	copy(header[9:], requestSalt)
	if corruptSalt {
		header[9] ^= 0xff
	}
	binary.BigEndian.PutUint16(header[9+len(requestSalt):], uint16(len(initial)))
	packet := append([]byte(nil), responseSalt...)
	packet = append(packet, stream.seal(header)...)
	if corruptSalt {
		// The client rejects the header before consuming response payload.
		// Sending payload here would block on net.Pipe.
		return writeFull(conn, packet)
	}
	packet = append(packet, stream.seal(initial)...)
	if len(subsequent) > 0 {
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(subsequent)))
		packet = append(packet, stream.seal(length)...)
		packet = append(packet, stream.seal(subsequent)...)
	}
	return writeFull(conn, packet)
}

func newBlackstoneTestPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return client, server
}

// TestBLACKSTONEStreamRoundTrip exercises both directions of the actual
// wire-format connection: first payload, post-handshake frames, encrypted
// response header and subsequent server frames.
func TestBLACKSTONEStreamRoundTrip(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newBlackstoneTestPipe(t)
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		req, err := decodeBlackstoneTestRequest(server, method)
		if err != nil {
			done <- err
			return
		}
		if req.destination.String() != "example.org:443" {
			done <- fmt.Errorf("target = %v", req.destination)
			return
		}
		if string(req.initialPayload) != "client-hello" {
			done <- fmt.Errorf("initial payload = %q", req.initialPayload)
			return
		}
		payload, err := readBlackstoneTestFrame(server, req.stream)
		if err != nil {
			done <- err
			return
		}
		if string(payload) != "client-next" {
			done <- fmt.Errorf("next payload = %q", payload)
			return
		}
		done <- sendBlackstoneTestResponse(server, method, req.salt, []byte("server-first"), []byte("server-next"), false)
	}()

	stream := method.DialEarlyConn(client, M.ParseSocksaddrHostPort("example.org", 443))
	for _, data := range []string{"client-hello", "client-next"} {
		n, err := stream.Write([]byte(data))
		if err != nil || n != len(data) {
			t.Fatalf("Write(%q) = %d, %v", data, n, err)
		}
	}
	got := make([]byte, len("server-firstserver-next"))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "server-firstserver-next" {
		t.Fatalf("response = %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Some TCP applications wait for a server banner before writing any bytes.
// BLACKSTONE must be able to send its first flight on the first Read, too.
func TestBLACKSTONEReadBeforeWrite(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newBlackstoneTestPipe(t)
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		req, err := decodeBlackstoneTestRequest(server, method)
		if err != nil {
			done <- err
			return
		}
		if len(req.initialPayload) != 0 {
			done <- fmt.Errorf("unexpected first-flight data: %q", req.initialPayload)
			return
		}
		done <- sendBlackstoneTestResponse(server, method, req.salt, []byte("server-banner"), nil, false)
	}()
	stream := method.DialEarlyConn(client, M.ParseSocksaddrHostPort("1.1.1.1", 25))
	buf := make([]byte, len("server-banner"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "server-banner" {
		t.Fatalf("server-first payload = %q", buf)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBLACKSTONERejectsWrongResponseSalt(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newBlackstoneTestPipe(t)
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		req, err := decodeBlackstoneTestRequest(server, method)
		if err != nil {
			done <- err
			return
		}
		done <- sendBlackstoneTestResponse(server, method, req.salt, []byte("invalid-response"), nil, true)
	}()
	stream := method.DialEarlyConn(client, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	if _, err := stream.Write(nil); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	if _, err := stream.Read(b); err == nil {
		t.Fatal("accepted response bound to wrong request salt")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBLACKSTONELargeFirstPayloadFraming(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newBlackstoneTestPipe(t)
	defer client.Close()
	defer server.Close()
	data := bytes.Repeat([]byte("0123456789abcdef"), 9500) // 152,000 bytes > 2 chunks
	done := make(chan error, 1)
	go func() {
		req, err := decodeBlackstoneTestRequest(server, method)
		if err != nil {
			done <- err
			return
		}
		got := append([]byte(nil), req.initialPayload...)
		for len(got) < len(data) {
			chunk, err := readBlackstoneTestFrame(server, req.stream)
			if err != nil {
				done <- err
				return
			}
			got = append(got, chunk...)
		}
		if !bytes.Equal(got, data) {
			done <- fmt.Errorf("large payload roundtrip mismatch (%d bytes)", len(got))
			return
		}
		done <- nil
	}()
	stream := method.DialEarlyConn(client, M.ParseSocksaddrHostPort("1.1.1.1", 80))
	n, err := stream.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("large Write = %d/%d: %v", n, len(data), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The legacy UOT payload has no version-2 handshake. The first encrypted SS
// destination is the old magic address; the decrypted byte stream then holds
// UOT v1's per-datagram destination, 2-byte size, and datagram body.
func TestBLACKSTONELegacyUOTWire(t *testing.T) {
	method, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newBlackstoneTestPipe(t)
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		req, err := decodeBlackstoneTestRequest(server, method)
		if err != nil {
			done <- err
			return
		}
		if req.destination.Fqdn != uot.LegacyMagicAddress {
			done <- fmt.Errorf("UOT target=%q", req.destination.Fqdn)
			return
		}
		want := []byte{0x00, 1, 1, 1, 1, 0, 53, 0, 9}
		want = append(want, []byte("dns-query")...)
		got := append([]byte(nil), req.initialPayload...)
		for len(got) < len(want) {
			part, err := readBlackstoneTestFrame(server, req.stream)
			if err != nil {
				done <- err
				return
			}
			got = append(got, part...)
		}
		if !bytes.Equal(got, want) {
			done <- fmt.Errorf("legacy UOT v1 framing does not match expected bytes: got %x", got)
			return
		}
		done <- nil
	}()
	stream := method.DialEarlyConn(client, uot.RequestDestination(uot.LegacyVersion))
	uotConn, err := (&uot.Client{Version: uot.LegacyVersion}).DialEarlyConn(stream, false, M.ParseSocksaddrHostPort("1.1.1.1", 53))
	if err != nil {
		t.Fatal(err)
	}
	// net.IPv4 returns a 16-byte IPv4-mapped IPv6 value; .To4() ensures
	// the 4-byte IPv4 representation expected by the explicit wire fixture.
	n, err := uotConn.WriteTo([]byte("dns-query"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1).To4(), Port: 53})
	if err != nil {
		t.Fatalf("uot.WriteTo failed after %d bytes: %v", n, err)
	}
	// Older sing/uot versions can count the framed write length rather than
	// only the datagram payload when vectorised writing is unavailable.
	// Verify the decrypted wire bytes above instead of depending on n.
	if n < len("dns-query") {
		t.Fatalf("uot.WriteTo reported too few bytes: %d", n)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
