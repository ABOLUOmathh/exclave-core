package v4_test

import (
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/serial"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon/testassist"
	v4 "github.com/exclavenetwork/exclave-core/v5/infra/conf/v4"
	"github.com/exclavenetwork/exclave-core/v5/proxy/vless"
	"github.com/exclavenetwork/exclave-core/v5/proxy/vless/inbound"
	"github.com/exclavenetwork/exclave-core/v5/proxy/vless/outbound"
)

func TestVLessOutbound(t *testing.T) {
	creator := func() cfgcommon.Buildable {
		return new(v4.VLessOutboundConfig)
	}

	testassist.RunMultiTestCase(t, []testassist.TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "example.com",
					"port": 443,
					"users": [
						{
							"id": "27848739-7e62-4138-9fd3-098a63964b6b",
							"encryption": "none",
							"level": 0
						}
					]
				}]
			}`,
			Parser: testassist.LoadJSON(creator),
			Output: &outbound.Config{
				Vnext: []*protocol.ServerEndpoint{
					{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Domain{
								Domain: "example.com",
							},
						},
						Port: 443,
						User: []*protocol.User{
							{
								Account: serial.ToTypedMessage(&vless.Account{
									Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
									Encryption: "none",
								}),
								Level: 0,
							},
						},
					},
				},
			},
		},
		{
			Input: `{
				"vnext": [{
					"address": "vless.heysocks.com",
					"port": 443,
					"users": [
						{
							"id": "f355229a-2465-01c6-b3cf-735aecd2df9c",
							"flow": "xtls-rprx-vision",
							"encryption": "none",
							"e": 1,
							"h": "3148b91dcbdd22fe2ccab2e1fb375a0e"
						}
					]
				}]
			}`,
			Parser: testassist.LoadJSON(creator),
			Output: &outbound.Config{
				Vnext: []*protocol.ServerEndpoint{
					{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Domain{
								Domain: "vless.heysocks.com",
							},
						},
						Port: 443,
						User: []*protocol.User{
							{
								Account: serial.ToTypedMessage(&vless.Account{
									Id:         "f355229a-2465-01c6-b3cf-735aecd2df9c",
									Flow:       "xtls-rprx-vision",
									Encryption: "none",
									E:          true,
									H:          "3148b91dcbdd22fe2ccab2e1fb375a0e",
								}),
							},
						},
					},
				},
			},
		},
	})
}

func TestVLessInbound(t *testing.T) {
	creator := func() cfgcommon.Buildable {
		return new(v4.VLessInboundConfig)
	}

	testassist.RunMultiTestCase(t, []testassist.TestCase{
		{
			Input: `{
				"clients": [
					{
						"id": "27848739-7e62-4138-9fd3-098a63964b6b",
						"level": 0,
						"email": "love@v2fly.org"
					}
				],
				"decryption": "none",
				"fallbacks": [
					{
						"dest": 80
					},
					{
						"alpn": "h2",
						"dest": "@/dev/shm/domain.socket",
						"xver": 2
					},
					{
						"path": "/innerws",
						"dest": "serve-ws-none"
					}
				]
			}`,
			Parser: testassist.LoadJSON(creator),
			Output: &inbound.Config{
				Clients: []*protocol.User{
					{
						Account: serial.ToTypedMessage(&vless.Account{
							Id: "27848739-7e62-4138-9fd3-098a63964b6b",
						}),
						Level: 0,
						Email: "love@v2fly.org",
					},
				},
				Decryption: "none",
				Fallbacks: []*inbound.Fallback{
					{
						Alpn: "",
						Path: "",
						Type: "tcp",
						Dest: "127.0.0.1:80",
						Xver: 0,
					},
					{
						Alpn: "h2",
						Path: "",
						Type: "unix",
						Dest: "@/dev/shm/domain.socket",
						Xver: 2,
					},
					{
						Alpn: "",
						Path: "/innerws",
						Type: "serve",
						Dest: "serve-ws-none",
						Xver: 0,
					},
				},
			},
		},
	})
}
