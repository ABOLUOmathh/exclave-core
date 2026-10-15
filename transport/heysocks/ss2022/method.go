package ss2022

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type Method struct {
	psk          []byte
	identityPSKs [][]byte
	eihPSKHashes [][identityHeaderLength]byte

	randReader io.Reader
	timeFunc   func() time.Time
}

func New(methodName, password string) (*Method, error) {
	if methodName != MethodAES128GCM {
		return nil, fmt.Errorf("heysocks ss2022: unsupported cipher %q in BLACKSTONE mode", methodName)
	}

	identities, master, err := ParseKeys(password)
	if err != nil {
		return nil, err
	}

	return &Method{
		psk:          append([]byte(nil), master...),
		identityPSKs: identities,
		eihPSKHashes: clientPSKHashes(identities, master),
		randReader:   rand.Reader,
		timeFunc:     time.Now,
	}, nil
}

func (m *Method) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	c := newClientConn(conn, destination, m)
	if _, err := c.ensureHandshake(nil); err != nil {
		return nil, err
	}
	return c, nil
}

func (m *Method) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return newClientConn(conn, destination, m)
}
