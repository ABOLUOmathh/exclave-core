package heysocksxhttp

import (
	"context"
	"fmt"

	core "github.com/exclavenetwork/exclave-core/v5"
	"github.com/exclavenetwork/exclave-core/v5/common"
	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
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

var _ proxy.Outbound = (*Client)(nil)

// Client implements the Exclave outbound API, not Mihomo's ProxyAdapter.
// Stage 2 enables TCP only. Native UDP and UOT are deliberately not advertised.
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
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
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return fmt.Errorf("heysocks XHTTP: destination not specified")
	}
	if outbound.Target.Network == net.Network_UDP {
		return fmt.Errorf("heysocks XHTTP: UDP/UOT outbound not yet implemented")
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

	rawDestination, err := serializeDestination(outbound.Target)
	if err != nil {
		return err
	}
	cipher, err := account.NewCipher()
	if err != nil {
		return err
	}

	conn, err := dialer.Dial(ctx, server.Destination())
	if err != nil {
		return err
	}
	defer conn.Close()

	stream := wire.NewConn(conn, cipher, rawDestination)
	if _, err := stream.Write(nil); err != nil {
		return fmt.Errorf("heysocks XHTTP: send destination: %w", err)
	}

	timeouts := c.policyManager.ForLevel(0).Timeouts
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, timeouts.ConnectionIdle)

	uplink := func() error {
		defer timer.SetTimeout(timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(stream), buf.UpdateActivity(timer))
	}
	downlink := func() error {
		defer timer.SetTimeout(timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(stream), link.Writer, buf.UpdateActivity(timer))
	}
	return task.Run(ctx, uplink, task.OnSuccess(downlink, task.Close(link.Writer)))
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
