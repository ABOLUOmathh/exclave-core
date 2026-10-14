package onesocks

import (
	"net"
	"testing"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	corenet "github.com/exclavenetwork/exclave-core/v5/common/net"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

func TestNativeUDPLoopback(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP(
		"udp4", nil, server.LocalAddr().(*net.UDPAddr),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	cipher, err := wire.NewStreamCipher(
		"aes-128-ctr", "onesocks-test-password",
	)
	if err != nil {
		t.Fatal(err)
	}

	packetConn, err := wire.NewPacketConn(
		internet.NewConnWrapper(client), cipher, 0,
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		dest corenet.Destination
	}{
		{
			"IPv4",
			corenet.UDPDestination(
				corenet.IPAddress(net.IPv4(8, 8, 8, 8)), 53,
			),
		},
		{
			"Domain",
			corenet.UDPDestination(
				corenet.DomainAddress("example.org"), 443,
			),
		},
		{
			"IPv6",
			corenet.UDPDestination(
				corenet.IPAddress(net.ParseIP("2001:db8::1")), 53,
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deadline := time.Now().Add(3 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)

			payload := []byte("hello-onesocks-udp")
			b := buf.New()
			if _, err := b.Write(payload); err != nil {
				b.Release()
				t.Fatal(err)
			}

			writer := &nativeUDPWriter{
				conn:        packetConn,
				serverAddr:  client.RemoteAddr(),
				destination: tc.dest,
			}

			if err := writer.WriteMultiBuffer(
				buf.MultiBuffer{b},
			); err != nil {
				t.Fatal(err)
			}

			// Simulate the server echoing one encrypted datagram.
			encrypted := make([]byte, 65535)
			n, from, err := server.ReadFromUDP(encrypted)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := server.WriteToUDP(encrypted[:n], from); err != nil {
				t.Fatal(err)
			}

			reader := &nativeUDPReader{conn: packetConn}
			received, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(received)

			if len(received) != 1 {
				t.Fatalf("received %d buffers", len(received))
			}

			if string(received[0].Bytes()) != string(payload) {
				t.Fatalf("payload mismatch")
			}

			if received[0].Endpoint == nil {
				t.Fatal("missing UDP endpoint")
			}

			got := received[0].Endpoint
			if got.Address.String() != tc.dest.Address.String() ||
				got.Port != tc.dest.Port {
				t.Fatalf(
					"endpoint mismatch: got %v, want %v",
					got, tc.dest,
				)
			}
		})
	}
}
