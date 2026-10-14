package onesocks

import (
	"bytes"
	"context"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/signal"
	"github.com/exclavenetwork/exclave-core/v5/common/task"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

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

		dest := w.destination
		if b.Endpoint != nil {
			dest = *b.Endpoint
		}

		address, err := serializeDestination(dest)
		if err != nil {
			return err
		}

		// Native OneSocks UDP plaintext:
		// SOCKS_ADDR(destination) || UDP payload
		plaintext := make([]byte, len(address)+len(b.Bytes()))
		copy(plaintext, address)
		copy(plaintext[len(address):], b.Bytes())

		n, err := w.conn.WriteTo(plaintext, w.serverAddr)
		if err != nil {
			return err
		}
		if n != len(plaintext) {
			return newError("onesocks UDP short write")
		}
	}

	return nil
}

type nativeUDPReader struct {
	conn net.PacketConn
}

func (r *nativeUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// Larger than ordinary buf.Size to avoid truncating
	// a valid encrypted UDP datagram.
	packet := make([]byte, 65535)

	n, _, err := r.conn.ReadFrom(packet)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(packet[:n])

	address, port, err := onesocksAddressSerializer.ReadAddressPort(
		nil,
		reader,
	)
	if err != nil {
		return nil, newError("onesocks UDP address decode failed").Base(err)
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

func (c *Client) processUDP(
	ctx context.Context,
	link *transport.Link,
	dialer internet.Dialer,
	server *protocol.ServerSpec,
	account *MemoryAccount,
	destination net.Destination,
) error {
	serverDest := server.Destination()
	serverDest.Network = net.Network_UDP

	rawConn, err := dialer.Dial(ctx, serverDest)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	cipher, err := wire.NewStreamCipher(
		account.CipherName,
		account.Password,
	)
	if err != nil {
		return err
	}

	packetConn, err := wire.NewPacketConn(
		internet.NewConnWrapper(rawConn),
		cipher,
		c.paddingLen,
	)
	if err != nil {
		return err
	}

	policy := c.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblock UDP ReadFrom when this session is canceled.
	go func() {
		<-ctx.Done()
		_ = rawConn.Close()
	}()

	timer := signal.CancelAfterInactivity(
		ctx,
		cancel,
		policy.Timeouts.ConnectionIdle,
	)

	writer := &nativeUDPWriter{
		conn:        packetConn,
		serverAddr:  rawConn.RemoteAddr(),
		destination: destination,
	}
	reader := &nativeUDPReader{
		conn: packetConn,
	}

	requestFunc := func() error {
		defer timer.SetTimeout(policy.Timeouts.DownlinkOnly)
		return buf.Copy(
			link.Reader,
			writer,
			buf.UpdateActivity(timer),
		)
	}

	responseFunc := func() error {
		defer timer.SetTimeout(policy.Timeouts.UplinkOnly)
		return buf.Copy(
			reader,
			link.Writer,
			buf.UpdateActivity(timer),
		)
	}

	responseDone := task.OnSuccess(
		responseFunc,
		task.Close(link.Writer),
	)

	return task.Run(ctx, requestFunc, responseDone)
}
