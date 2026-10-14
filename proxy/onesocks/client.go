package onesocks

import (
	"context"
	"time"

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
	"github.com/exclavenetwork/exclave-core/v5/transport/heysocks/onesocks"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

var (
	_ proxy.Outbound = (*Client)(nil)
)

var (
	_ proxy.OutboundWithSingUot = (*Client)(nil)
)

type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	paddingLen    int
	udp           bool
	uot           bool
	uotVersion    uint32
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

		paddingLen: int(config.GetPaddingLen()),

		udp:        config.Udp,
		uot:        config.Uot,
		uotVersion: config.UotVersion,
	}
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

	user := server.PickUser()

	if user == nil {
		return newError("onesocks user missing")
	}

	account, ok := user.Account.(*MemoryAccount)

	if !ok {
		return newError("invalid onesocks account")
	}

	destination :=
		outbound.Target

	if destination.Network == net.Network_UDP {
		if c.uot {
			return c.processUOT(
				ctx, link, dialer, server, account, destination,
			)
		}
		if c.udp {
			return c.processUDP(
				ctx, link, dialer, server, account, destination,
			)
		}
		return newError("onesocks UDP disabled")
	}

	conn, err :=
		dialer.Dial(
			ctx,
			server.Destination(),
		)

	if err != nil {
		return err
	}

	defer conn.Close()

	rawDestination, err :=
		serializeDestination(destination)

	if err != nil {
		return err
	}

	cipher, err :=
		onesocks.NewStreamCipher(
			account.CipherName,
			account.Password,
		)

	if err != nil {
		return err
	}

	stream, err :=
		onesocks.NewConn(
			conn,
			cipher,
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

func (c *Client) processUOT(
	ctx context.Context,
	link *transport.Link,
	dialer internet.Dialer,
	server *protocol.ServerSpec,
	account *MemoryAccount,
	destination net.Destination,
) error {
	version := c.uotVersion
	if version != 0 && version != 1 && version != 2 {
		return newError("unsupported onesocks UOT version: ", version)
	}

	magicAddress := uot.MagicAddressV2
	if version == 1 {
		magicAddress = uot.MagicAddressV1
	}

	uotDestination := net.Destination{
		Network: net.Network_TCP,
		Address: net.DomainAddress(magicAddress),
		Port:    0,
	}

	rawDestination, err := serializeDestination(uotDestination)
	if err != nil {
		return err
	}

	conn, err := dialer.Dial(ctx, server.Destination())
	if err != nil {
		return err
	}
	defer conn.Close()

	cipher, err := onesocks.NewStreamCipher(
		account.CipherName,
		account.Password,
	)
	if err != nil {
		return err
	}

	stream, err := onesocks.NewConn(
		conn,
		cipher,
		rawDestination,
		c.paddingLen,
	)
	if err != nil {
		return err
	}

	if _, err := stream.Write(nil); err != nil {
		return err
	}

	var uotWriter buf.Writer
	var uotReader buf.Reader

	if version == 1 {
		uotWriter = uot.NewWriterV1(
			buf.NewWriter(stream),
			destination,
		)
		uotReader = uot.NewReaderV1(
			buf.NewReader(stream),
		)
	} else {
		uotWriter = uot.NewWriterV2(
			buf.NewWriter(stream),
			destination,
		)
		uotReader = uot.NewReaderV2(
			buf.NewReader(stream),
		)
	}

	p := c.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	timer := signal.CancelAfterInactivity(
		ctx,
		cancel,
		p.Timeouts.ConnectionIdle,
	)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)

		return buf.Copy(
			link.Reader,
			uotWriter,
			buf.UpdateActivity(timer),
		)
	}

	responseFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)

		return buf.Copy(
			uotReader,
			link.Writer,
			buf.UpdateActivity(timer),
		)
	}

	responseDone := task.OnSuccess(
		responseFunc,
		task.Close(link.Writer),
	)

	return task.Run(
		ctx,
		requestFunc,
		responseDone,
	)
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

func (c *Client) SingUotEnabled() bool {

	return c.uot

}
