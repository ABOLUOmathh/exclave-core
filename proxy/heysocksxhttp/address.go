package heysocksxhttp

import (
	"bytes"
	"fmt"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
)

// SOCKS address format used by HeySocks XHTTP (IPv4, IPv6, or domain + port).
var addressParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

func serializeDestination(destination net.Destination) ([]byte, error) {
	var buffer bytes.Buffer
	if err := addressParser.WriteAddressPort(&buffer, destination.Address, destination.Port); err != nil {
		return nil, fmt.Errorf("heysocks XHTTP: serialize destination: %w", err)
	}
	return buffer.Bytes(), nil
}
