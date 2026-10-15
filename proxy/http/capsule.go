package http

import (
	"encoding/binary"
	"io"
	"math"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	default:
		return 8
	}
}

var (
	_ buf.Writer = (*uotWriter)(nil)
	_ buf.Reader = (*uotReader)(nil)
)

type uotReader struct {
	conn net.Conn
}

func newUoTReader(conn net.Conn) *uotReader {
	return &uotReader{
		conn: conn,
	}
}

func (r *uotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
start:
	capsuleType, _, err := readVarint(r.conn)
	if err != nil {
		return nil, err
	}
	capsuleLength, _, err := readVarint(r.conn)
	if err != nil {
		return nil, err
	}
	if capsuleLength > math.MaxInt32 {
		return nil, newError("invalid capsule length")
	}
	if capsuleType != 0 {
		_, err = io.CopyN(io.Discard, r.conn, int64(capsuleLength))
		if err != nil {
			return nil, err
		}
		goto start
	}
	contextID, contextIDLength, err := readVarint(r.conn)
	if err != nil {
		return nil, err
	}
	payloadLength := int32(capsuleLength) - int32(contextIDLength)
	if payloadLength < 0 {
		return nil, newError("invalid payload length")
	}
	if contextID != 0 {
		_, err = io.CopyN(io.Discard, r.conn, int64(payloadLength))
		if err != nil {
			return nil, err
		}
		goto start
	}
	b := buf.NewWithSize(payloadLength)
	if _, err = b.ReadFullFrom(r.conn, payloadLength); err != nil {
		b.Release()
		return nil, err
	}
	return buf.MultiBuffer{b}, nil
}

func readVarint(reader io.Reader) (uint64, int, error) {
	var b [1]byte
	_, err := io.ReadFull(reader, b[:])
	if err != nil {
		return 0, 0, err
	}
	length := 1 << (b[0] >> 6)
	value := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		_, err = io.ReadFull(reader, b[:])
		if err != nil {
			return 0, 0, err
		}
		value = value<<8 | uint64(b[0])
	}
	return value, length, nil
}

type uotWriter struct {
	conn net.Conn
	dest net.Destination
}

func newUoTWriter(conn net.Conn, dest net.Destination) *uotWriter {
	return &uotWriter{
		conn: conn,
		dest: dest,
	}
}

func (w *uotWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b.Endpoint != nil && *b.Endpoint != w.dest {
			newError("CONNECT-UDP can not have different destination addresses").AtDebug().WriteToLog()
			continue
		}
		capsuleLength := uint64(1 + b.Len())
		payload := buf.NewWithSize(1 + int32(varintLen(capsuleLength)) + 1 + b.Len())
		// Capsule Type
		payload.WriteByte(0x00)
		// Capsule Length
		switch varintLen(capsuleLength) {
		case 1:
			payload.WriteByte(byte(capsuleLength))
		case 2:
			var v [2]byte
			binary.BigEndian.PutUint16(v[:], uint16(capsuleLength)|0x4000)
			payload.Write(v[:])
		case 4:
			var v [4]byte
			binary.BigEndian.PutUint32(v[:], uint32(capsuleLength)|0x80000000)
			payload.Write(v[:])
		default:
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], capsuleLength|0xc000000000000000)
			payload.Write(v[:])
		}
		// Capsule Value
		payload.WriteByte(0x00)  // Context ID
		payload.Write(b.Bytes()) // UDP Proxying Payload
		_, err := w.conn.Write(payload.Bytes())
		payload.Release()
		if err != nil {
			return err
		}
	}
	return nil
}
