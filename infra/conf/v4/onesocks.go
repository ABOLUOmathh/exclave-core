package v4

import (
	"github.com/golang/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/serial"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/proxy/onesocks"
	onesocksWire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
)

type OneSocksServerTarget struct {
	Address  *cfgcommon.Address `json:"address"`
	Port     uint16             `json:"port"`
	Cipher   string             `json:"cipher"`
	Password string             `json:"password"`
}

type OneSocksClientConfig struct {
	Servers    []*OneSocksServerTarget `json:"servers"`
	PaddingLen string                  `json:"paddingLen"`
	UDP        bool                    `json:"udp"`
	UOT        bool                    `json:"uot"`
	UOTVersion uint32                  `json:"uotVersion"`
}

func (v *OneSocksClientConfig) Build() (proto.Message, error) {
	config := new(onesocks.ClientConfig)

	paddingLen, err := onesocksWire.ParsePaddingLen(v.PaddingLen)
	if err != nil {
		return nil, newError("invalid onesocks paddingLen: ", err)
	}

	config.PaddingLen = uint32(paddingLen)
	config.Udp = v.UDP
	config.Uot = v.UOT
	config.UotVersion = v.UOTVersion

	config.Server = make([]*protocol.ServerEndpoint, len(v.Servers))

	for idx, server := range v.Servers {
		if server == nil || server.Address == nil {
			return nil, newError("onesocks server address is not set")
		}

		account := &onesocks.Account{
			Password: server.Password,
			Cipher:   server.Cipher,
		}

		config.Server[idx] = &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: []*protocol.User{
				{
					Account: serial.ToTypedMessage(account),
				},
			},
		}
	}

	return config, nil
}
