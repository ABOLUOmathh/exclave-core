package xhttp

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// PacketConn provides the wire envelope only. Higher layers in Exclave are
// responsible for serializing the destination and fixing the remote server.
type PacketConn struct {
	net.PacketConn
	cipher  *StreamCipher
	random  io.Reader
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func NewPacketConn(conn net.PacketConn, c *StreamCipher) *PacketConn {
	return &PacketConn{PacketConn: conn, cipher: c, random: rand.Reader}
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	datagram, err := PackPacket(c.cipher, p, c.random)
	if err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(datagram, addr)
	if err != nil {
		return 0, err
	}
	if n != len(datagram) {
		return 0, fmt.Errorf("xhttp: short UDP write")
	}
	return len(p), nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// UDP packets need headroom for the wire envelope. Avoid truncating a
	// datagram into the caller's plaintext-sized output buffer.
	packet := make([]byte, 65535)
	n, addr, err := c.PacketConn.ReadFrom(packet)
	if err != nil {
		return n, addr, err
	}
	plaintext, err := UnpackPacket(c.cipher, packet[:n])
	if err != nil {
		return 0, addr, err
	}
	if len(plaintext) > len(p) {
		return 0, addr, fmt.Errorf("xhttp: UDP plaintext exceeds caller buffer")
	}
	copy(p, plaintext)
	return len(plaintext), addr, nil
}
