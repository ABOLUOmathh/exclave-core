package xhttp

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// Conn implements the XHTTP/xstream encrypted TCP data path over a net.Conn.
// The caller sends the destination once with Write(nil) before payload data.
type Conn struct {
	net.Conn
	cipher      *StreamCipher
	destination []byte
	random      io.Reader
	writeMu     sync.Mutex
	readMu      sync.Mutex
	writer      cipher.Stream
	reader      cipher.Stream
}

func NewConn(conn net.Conn, c *StreamCipher, destination []byte) *Conn {
	return newConnWithRandom(conn, c, destination, rand.Reader)
}

func newConnWithRandom(conn net.Conn, c *StreamCipher, dest []byte, random io.Reader) *Conn {
	if random == nil {
		random = rand.Reader
	}
	return &Conn{Conn: conn, cipher: c, destination: append([]byte(nil), dest...), random: random}
}

func (c *Conn) initWriter() error {
	if c.writer != nil {
		return nil
	}
	header, iv, err := createBootstrap(c.cipher, "tcp", c.random)
	if err != nil {
		return err
	}
	cipherStream, err := c.cipher.Encrypter(iv)
	if err != nil {
		return err
	}
	if err := writeAll(c.Conn, header); err != nil {
		return fmt.Errorf("xhttp: send bootstrap: %w", err)
	}
	c.writer = cipherStream
	return nil
}

func (c *Conn) initReader() error {
	if c.reader != nil {
		return nil
	}
	iv, err := readBootstrap(c.Conn, c.cipher)
	if err != nil {
		return err
	}
	cipherStream, err := c.cipher.Decrypter(iv)
	if err != nil {
		return err
	}
	c.reader = cipherStream
	return nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.initWriter(); err != nil {
		return 0, err
	}
	payload := p
	if p == nil {
		payload = c.destination
	}
	if len(payload) == 0 {
		return 0, nil
	}
	encrypted := make([]byte, len(payload))
	c.writer.XORKeyStream(encrypted, payload)
	if err := writeAll(c.Conn, encrypted); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.initReader(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.reader.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
