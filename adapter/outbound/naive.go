package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	naiveTransport "github.com/metacubex/mihomo/transport/naive"
	"github.com/metacubex/mihomo/transport/vmess"
)

const (
	// naiveProtocolHTTP2 is the only transport this outbound implements.
	// naiveproxy also defines an HTTP/3 variant, which is not wired up yet.
	naiveProtocolHTTP2 = "http2"
	// naiveDefaultFingerprint keeps the Chrome ClientHello that gives naive its
	// cover, unless a profile deliberately asks for something else.
	naiveDefaultFingerprint = "chrome"
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
	if option.Protocol != "" && option.Protocol != naiveProtocolHTTP2 {
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

// ProxyInfo implements C.ProxyAdapter
func (naive *Naive) ProxyInfo() C.ProxyInfo {
	info := naive.Base.ProxyInfo()
	info.DialerProxy = naive.option.DialerProxy
	return info
}
