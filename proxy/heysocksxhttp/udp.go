package heysocksxhttp

import (
	"bytes"
	"context"
	"fmt"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/signal"
	"github.com/exclavenetwork/exclave-core/v5/common/task"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/xhttp"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// Native HeySocks UDP plaintext is SOCKS destination followed by the payload.
// The xstream envelope is handled by wire.PacketConn.
type nativeUDPWriter struct {
	conn        net.PacketConn
	serverAddr  net.Addr
	destination net.Destination
}

func (w *nativeUDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b == nil {
			continue
		}
		target := w.destination
		if b.Endpoint != nil {
			target = *b.Endpoint
		}
		address, err := serializeDestination(target)
		if err != nil {
			return err
		}
		plaintext := make([]byte, len(address)+len(b.Bytes()))
		copy(plaintext, address)
		copy(plaintext[len(address):], b.Bytes())
		n, err := w.conn.WriteTo(plaintext, w.serverAddr)
		if err != nil {
			return err
		}
		if n != len(plaintext) {
			return fmt.Errorf("heysocks XHTTP: UDP short write")
		}
	}
	return nil
}

type nativeUDPReader struct{ conn net.PacketConn }

func (r *nativeUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packet := make([]byte, 65535)
	n, _, err := r.conn.ReadFrom(packet)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(packet[:n])
	address, port, err := addressParser.ReadAddressPort(nil, reader)
	if err != nil {
		return nil, fmt.Errorf("heysocks XHTTP: UDP address decode: %w", err)
	}
	payloadBytes := packet[n-reader.Len() : n]
	payload := buf.NewWithSize(int32(len(payloadBytes)))
	if _, err := payload.Write(payloadBytes); err != nil {
		payload.Release()
		return nil, err
	}
	endpoint := net.UDPDestination(address, port)
	payload.Endpoint = &endpoint
	return buf.MultiBuffer{payload}, nil
}

func (c *Client) processUDP(ctx context.Context, link *transport.Link, dialer internet.Dialer, server *protocol.ServerSpec, account *MemoryAccount, destination net.Destination) error {
	serverDestination := server.Destination()
	serverDestination.Network = net.Network_UDP
	rawConn, err := dialer.Dial(ctx, serverDestination)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	cipher, err := account.NewCipher()
	if err != nil {
		return err
	}
	packetConn := wire.NewPacketConn(internet.NewConnWrapper(rawConn), cipher)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = rawConn.Close()
	}()

	timeouts := c.policyManager.ForLevel(0).Timeouts
	timer := signal.CancelAfterInactivity(ctx, cancel, timeouts.ConnectionIdle)
	writer := &nativeUDPWriter{
		conn: packetConn, serverAddr: rawConn.RemoteAddr(), destination: destination,
	}
	reader := &nativeUDPReader{conn: packetConn}
	uplink := func() error {
		defer timer.SetTimeout(timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}
	downlink := func() error {
		defer timer.SetTimeout(timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}
	return task.Run(ctx, uplink, task.OnSuccess(downlink, task.Close(link.Writer)))
}
