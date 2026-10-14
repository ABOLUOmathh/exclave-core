package heysocksxhttp

import (
	"context"
	"fmt"

	core "github.com/exclavenetwork/exclave-core/v5"
	"github.com/exclavenetwork/exclave-core/v5/common"
	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/net/uot"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
	"github.com/exclavenetwork/exclave-core/v5/common/signal"
	"github.com/exclavenetwork/exclave-core/v5/common/task"
	"github.com/exclavenetwork/exclave-core/v5/features/policy"
	"github.com/exclavenetwork/exclave-core/v5/proxy"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	wire "github.com/exclavenetwork/exclave-core/v5/transport/heysocks/xhttp"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

var (
	_ proxy.Outbound            = (*Client)(nil)
	_ proxy.OutboundWithSingUot = (*Client)(nil)
)

// Client uses Exclave's native outbound interfaces. The custom xstream wire
// format is isolated in transport/heysocks/xhttp.
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	udp           bool
	uot           bool
	uotVersion    uint32
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("heysocks XHTTP: nil client config")
	}
	if config.GetUotVersion() > 2 {
		return nil, fmt.Errorf("heysocks XHTTP: unsupported UOT version: %d", config.GetUotVersion())
	}
	serverList := protocol.NewServerList()
	for _, endpoint := range config.Server {
		server, err := protocol.NewServerSpecFromPB(endpoint)
		if err != nil {
			return nil, err
		}
		serverList.AddServer(server)
	}
	if serverList.Size() == 0 {
		return nil, fmt.Errorf("heysocks XHTTP: no target server")
	}
	v := core.MustFromContext(ctx)
	return &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		udp:           config.GetUdp(),
		uot:           config.GetUot(),
		uotVersion:    config.GetUotVersion(),
	}, nil
}

func (c *Client) SingUotEnabled() bool { return c.uot }

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return fmt.Errorf("heysocks XHTTP: destination not specified")
	}
	server := c.serverPicker.PickServer()
	user := server.PickUser()
	if user == nil {
		return fmt.Errorf("heysocks XHTTP: server account missing")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return fmt.Errorf("heysocks XHTTP: invalid account")
	}
	if outbound.Target.Network == net.Network_UDP {
		if c.uot {
			return c.processUOT(ctx, link, dialer, server, account, outbound.Target)
		}
		if c.udp {
			return c.processUDP(ctx, link, dialer, server, account, outbound.Target)
		}
		return fmt.Errorf("heysocks XHTTP: UDP disabled")
	}
	return c.processTCP(ctx, link, dialer, server, account, outbound.Target)
}

func (c *Client) dialStream(ctx context.Context, dialer internet.Dialer, server *protocol.ServerSpec, account *MemoryAccount, target net.Destination) (*wire.Conn, error) {
	rawDestination, err := serializeDestination(target)
	if err != nil {
		return nil, err
	}
	streamCipher, err := account.NewCipher()
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial(ctx, server.Destination())
	if err != nil {
		return nil, err
	}
	stream := wire.NewConn(conn, streamCipher, rawDestination)
	if _, err := stream.Write(nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("heysocks XHTTP: send destination: %w", err)
	}
	return stream, nil
}

func (c *Client) processTCP(ctx context.Context, link *transport.Link, dialer internet.Dialer, server *protocol.ServerSpec, account *MemoryAccount, target net.Destination) error {
	stream, err := c.dialStream(ctx, dialer, server, account, target)
	if err != nil {
		return err
	}
	defer stream.Close()
	return c.relay(ctx, link, buf.NewReader(stream), buf.NewWriter(stream))
}

func uotMagicTarget(version uint32) (net.Destination, error) {
	magicAddress := uot.MagicAddressV2
	switch version {
	case 0, 2:
		// HeySocks version 0 is the current (v2) path, not the legacy v1.
	case 1:
		magicAddress = uot.MagicAddressV1
	default:
		return net.Destination{}, fmt.Errorf("heysocks XHTTP: unsupported UOT version: %d", version)
	}
	return net.Destination{
		Network: net.Network_TCP,
		Address: net.DomainAddress(magicAddress),
		Port:    0,
	}, nil
}

func (c *Client) processUOT(ctx context.Context, link *transport.Link, dialer internet.Dialer, server *protocol.ServerSpec, account *MemoryAccount, target net.Destination) error {
	magicDestination, err := uotMagicTarget(c.uotVersion)
	if err != nil {
		return err
	}
	stream, err := c.dialStream(ctx, dialer, server, account, magicDestination)
	if err != nil {
		return err
	}
	defer stream.Close()

	var reader buf.Reader
	var writer buf.Writer
	if c.uotVersion == 1 {
		reader = uot.NewReaderV1(buf.NewReader(stream))
		writer = uot.NewWriterV1(buf.NewWriter(stream), target)
	} else {
		reader = uot.NewReaderV2(buf.NewReader(stream))
		writer = uot.NewWriterV2(buf.NewWriter(stream), target)
	}
	return c.relay(ctx, link, reader, writer)
}

func (c *Client) relay(ctx context.Context, link *transport.Link, reader buf.Reader, writer buf.Writer) error {
	timeouts := c.policyManager.ForLevel(0).Timeouts
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, timeouts.ConnectionIdle)

	uplink := func() error {
		defer timer.SetTimeout(timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}
	downlink := func() error {
		defer timer.SetTimeout(timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}
	return task.Run(ctx, uplink, task.OnSuccess(downlink, task.Close(link.Writer)))
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
