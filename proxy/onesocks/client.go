package onesocks

import (
	"context"
	"time"

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
	"github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

var (
	_ proxy.Outbound = (*Client)(nil)
)

type Client struct {
	serverPicker protocol.ServerPicker

	policyManager policy.Manager

	cipher *onesocks.StreamCipher

	paddingLen int
}

func NewClient(
	ctx context.Context,
	config *ClientConfig,
) (*Client, error) {

	serverList := protocol.NewServerList()

	for _, rec := range config.Server {

		s, err := protocol.NewServerSpecFromPB(rec)

		if err != nil {
			return nil, err
		}

		serverList.AddServer(s)

	}

	if serverList.Size() == 0 {
		return nil, newError("0 target server")
	}

	v := core.MustFromContext(ctx)

	c := &Client{

		serverPicker: protocol.NewRoundRobinServerPicker(serverList),

		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),

		paddingLen: 0,
	}

	cipher, err :=
		onesocks.NewStreamCipher(
			"AES-128-CTR",
			config.PaddingLen,
		)

	if err != nil {
		return nil, err
	}

	c.cipher = cipher

	return c, nil

}

func (c *Client) Process(
	ctx context.Context,
	link *transport.Link,
	dialer internet.Dialer,
) error {

	outbound :=
		session.OutboundFromContext(ctx)

	if outbound == nil ||
		!outbound.Target.IsValid() {

		return newError(
			"target not specified",
		)

	}

	server :=
		c.serverPicker.PickServer()

	conn, err :=
		dialer.Dial(
			ctx,
			server.Destination(),
		)

	if err != nil {
		return err
	}

	defer conn.Close()

	destination :=
		outbound.Target

	rawDestination, err :=
		serializeDestination(destination)

	if err != nil {
		return err
	}

	stream, err :=
		onesocks.NewConn(
			conn,
			c.cipher,
			rawDestination,
			c.paddingLen,
		)

	if err != nil {
		return err
	}

	if _, err := stream.Write(nil); err != nil {
		return err
	}

	p := c.policyManager.ForLevel(0)

	ctx, cancel :=
		context.WithCancel(ctx)

	defer cancel()

	timer :=
		signal.CancelAfterInactivity(
			ctx,
			cancel,
			p.Timeouts.ConnectionIdle,
		)

	requestFunc := func() error {

		defer timer.SetTimeout(
			p.Timeouts.DownlinkOnly,
		)

		return buf.Copy(
			link.Reader,
			buf.NewWriter(stream),
			buf.UpdateActivity(timer),
		)

	}

	responseFunc := func() error {

		defer timer.SetTimeout(
			p.Timeouts.UplinkOnly,
		)

		return buf.Copy(
			buf.NewReader(stream),
			link.Writer,
			buf.UpdateActivity(timer),
		)

	}

	responseDone :=
		task.OnSuccess(
			responseFunc,
			task.Close(link.Writer),
		)

	if err := task.Run(
		ctx,
		requestFunc,
		responseDone,
	); err != nil {

		return err
	}

	return nil

}

func init() {

	common.Must(
		common.RegisterConfig(
			(*ClientConfig)(nil),
			func(
				ctx context.Context,
				config interface{},
			) (interface{}, error) {

				return NewClient(
					ctx,
					config.(*ClientConfig),
				)

			},
		),
	)

}

var _ = time.Second
var _ = net.AnyIP
