package v4

import (
	"github.com/golang/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/serial"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/proxy/heysocksxhttp"
)

// HeySocksXHTTPServerTarget is the per-server input in Exclave v4 JSON.
type HeySocksXHTTPServerTarget struct {
	Address  *cfgcommon.Address `json:"address"`
	Port     uint16             `json:"port"`
	Cipher   string             `json:"cipher"`
	Password string             `json:"password"`
	FakeTCP  string             `json:"fakeTcp"`
	FakeUDP  string             `json:"fakeUdp"`
}

type HeySocksXHTTPClientConfig struct {
	Servers    []*HeySocksXHTTPServerTarget `json:"servers"`
	UDP        bool                         `json:"udp"`
	UOT        bool                         `json:"uot"`
	UOTVersion uint32                       `json:"uotVersion"`
	PaddingLen string                       `json:"paddingLen"`
	E          bool                         `json:"e"`
	H          string                       `json:"h"`
}

func (v *HeySocksXHTTPClientConfig) Build() (proto.Message, error) {
	if v.H != "" {
		return nil, newError("heysocks XHTTP: option h is unsupported")
	}
	if v.UOTVersion > 2 {
		return nil, newError("heysocks XHTTP: unsupported UOT version")
	}
	// Like the Mihomo compatibility path, e and paddingLen are carried through,
	// but have no extra xstream runtime behavior.
	config := &heysocksxhttp.ClientConfig{
		Udp:        v.UDP,
		Uot:        v.UOT,
		UotVersion: v.UOTVersion,
		PaddingLen: v.PaddingLen,
		E:          v.E,
		H:          v.H,
	}
	if len(v.Servers) == 0 {
		return nil, newError("heysocks XHTTP: no server configured")
	}
	config.Server = make([]*protocol.ServerEndpoint, len(v.Servers))
	for i, server := range v.Servers {
		if server == nil || server.Address == nil {
			return nil, newError("heysocks XHTTP: missing server address")
		}
		account := &heysocksxhttp.Account{
			Cipher:   server.Cipher,
			Password: server.Password,
			FakeTcp:  server.FakeTCP,
			FakeUdp:  server.FakeUDP,
		}
		config.Server[i] = &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User:    []*protocol.User{{Account: serial.ToTypedMessage(account)}},
		}
	}
	return config, nil
}
