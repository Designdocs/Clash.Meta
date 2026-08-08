package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	naiveTransport "github.com/metacubex/mihomo/transport/naive"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/quic-go"
)

const (
	// naiveProtocolHTTP2 carries the tunnel over TLS + HTTP/2 on TCP, which is
	// what a naive server offers unless it was set up for QUIC as well.
	naiveProtocolHTTP2 = "http2"
	// naiveProtocolHTTP3 carries it over QUIC + HTTP/3 instead, on the same
	// port number but over UDP.
	naiveProtocolHTTP3 = "http3"
	// naiveDefaultFingerprint keeps the Chrome ClientHello that gives naive its
	// cover, unless a profile deliberately asks for something else. It only
	// reaches the HTTP/2 path — see naive.PrepareH3TLS.
	naiveDefaultFingerprint = "chrome"
	// naiveH3KeepAlivePeriod matches what quic-go itself uses, so an idle
	// tunnel is not the thing that stands out on the wire.
	naiveH3KeepAlivePeriod = 10 * time.Second
	// naiveH3IdleTimeout has to outlive a quiet interactive session; the QUIC
	// default of 30s would drop one.
	naiveH3IdleTimeout = 300 * time.Second
)

type Naive struct {
	*Base
	option    *NaiveOption
	tlsConfig *vmess.TLSConfig
}

type NaiveOption struct {
	BasicOption
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	Username          string            `proxy:"username,omitempty"`
	Password          string            `proxy:"password"`
	Protocol          string            `proxy:"protocol,omitempty"`
	SNI               string            `proxy:"sni,omitempty"`
	ALPN              []string          `proxy:"alpn,omitempty"`
	ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string            `proxy:"fingerprint,omitempty"`
	ECHOpts           ECHOptions        `proxy:"ech-opts,omitempty"`
	Headers           map[string]string `proxy:"headers,omitempty"`
	UDP               bool              `proxy:"udp,omitempty"`
}

func NewNaive(option NaiveOption) (*Naive, error) {
	if option.Server == "" || option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("invalid naive server or port")
	}
	if strings.TrimSpace(option.Password) == "" {
		return nil, errors.New("naive password is required")
	}
	if option.Protocol == "" {
		option.Protocol = naiveProtocolHTTP2
	}
	if option.Protocol != naiveProtocolHTTP2 && option.Protocol != naiveProtocolHTTP3 {
		return nil, fmt.Errorf("unsupported naive protocol: %s", option.Protocol)
	}
	if option.ClientFingerprint == "" {
		option.ClientFingerprint = naiveDefaultFingerprint
	}
	if option.ClientFingerprint != "none" {
		if _, ok := tlsC.GetFingerprint(option.ClientFingerprint); !ok {
			return nil, fmt.Errorf("unsupported naive client-fingerprint: %s", option.ClientFingerprint)
		}
	}
	if option.UDP {
		// Refusing the node over this would take the whole profile down, so
		// say it plainly once and carry the TCP half.
		log.Warnln("naive proxy %s requested udp, which this core does not carry yet; TCP only", option.Name)
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	tlsHost := option.SNI
	if tlsHost == "" {
		tlsHost = option.Server
	}

	outbound := &Naive{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Naive,
			ProviderName: option.ProviderName,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		tlsConfig: &vmess.TLSConfig{
			Host:              tlsHost,
			SkipCertVerify:    option.SkipCertVerify,
			NextProtos:        option.ALPN,
			FingerPrint:       option.Fingerprint,
			ClientFingerprint: option.ClientFingerprint,
			ECH:               echConfig,
		},
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// DialContext implements C.ProxyAdapter
func (naive *Naive) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if naive.option.Protocol == naiveProtocolHTTP3 {
		return naive.dialHTTP3(ctx, metadata)
	}
	raw, err := naive.dialer.DialContext(ctx, "tcp", naive.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", naive.addr, err)
	}
	defer func() { safeConnClose(raw, err) }()

	connection, err := naiveTransport.DialContext(ctx, raw, naiveTransport.ClientConfig{
		Username:     naive.option.Username,
		Password:     naive.option.Password,
		ExtraHeaders: naive.option.Headers,
		TLSConfig:    naive.tlsConfig,
	}, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(connection, naive), nil
}

// dialHTTP3 carries the same CONNECT handshake over QUIC. One QUIC connection
// serves one tunnel, matching what the HTTP/2 path does with its socket: both
// spend a single round trip per dial, and neither leaves a shared connection
// alive for a peer to fingerprint across tunnels.
func (naive *Naive) dialHTTP3(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	tlsConfig, err := naiveTransport.PrepareH3TLS(ctx, naiveTransport.ClientConfig{TLSConfig: naive.tlsConfig})
	if err != nil {
		return nil, err
	}
	packetConn, quicConnection, err := common.DialQuic(ctx, naive.addr, naive.DialOptions(), naive.dialer, tlsConfig, &quic.Config{
		// The server has no reason to open streams towards the client, and a
		// naive server never does.
		MaxIncomingStreams: -1,
		KeepAlivePeriod:    naiveH3KeepAlivePeriod,
		MaxIdleTimeout:     naiveH3IdleTimeout,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", naive.addr, err)
	}
	closeTransport := func() error {
		return errors.Join(quicConnection.CloseWithError(0, ""), packetConn.Close())
	}
	connection, err := naiveTransport.DialH3Context(ctx, quicConnection, naiveTransport.ClientConfig{
		Username:     naive.option.Username,
		Password:     naive.option.Password,
		ExtraHeaders: naive.option.Headers,
		TLSConfig:    naive.tlsConfig,
	}, metadata.RemoteAddress(), closeTransport)
	if err != nil {
		_ = closeTransport()
		return nil, err
	}
	return NewConn(connection, naive), nil
}

// ProxyInfo implements C.ProxyAdapter
func (naive *Naive) ProxyInfo() C.ProxyInfo {
	info := naive.Base.ProxyInfo()
	info.DialerProxy = naive.option.DialerProxy
	return info
}
