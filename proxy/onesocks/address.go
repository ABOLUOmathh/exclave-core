package onesocks

import (
	"bytes"
	"fmt"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
)

// OneSocks uses SOCKS5 address encoding:
//
// IPv4:
//
//	0x01 + 4 bytes address + uint16 port
//
// Domain:
//
//	0x03 + uint8 length + domain + uint16 port
//
// IPv6:
//
//	0x04 + 16 bytes address + uint16 port
var onesocksAddressSerializer = protocol.NewAddressParser(
	protocol.AddressFamilyByte(
		0x01,
		net.AddressFamilyIPv4,
	),
	protocol.AddressFamilyByte(
		0x04,
		net.AddressFamilyIPv6,
	),
	protocol.AddressFamilyByte(
		0x03,
		net.AddressFamilyDomain,
	),
)

func serializeDestination(
	destination net.Destination,
) ([]byte, error) {

	var buffer bytes.Buffer

	if err := onesocksAddressSerializer.WriteAddressPort(
		&buffer,
		destination.Address,
		destination.Port,
	); err != nil {

		return nil, fmt.Errorf(
			"onesocks: serialize destination: %w",
			err,
		)
	}

	return buffer.Bytes(), nil
}
