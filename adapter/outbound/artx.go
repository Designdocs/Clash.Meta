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
	artxTransport "github.com/metacubex/mihomo/transport/artx"
	"github.com/metacubex/mihomo/transport/vmess"
)

type ArtX struct {
	*Base
	option    *ArtXOption
	tlsConfig *vmess.TLSConfig
}

type ArtXOption struct {
	BasicOption
	Name              string     `proxy:"name"`
	Server            string     `proxy:"server"`
	Port              int        `proxy:"port"`
	Password          string     `proxy:"password"`
	ALPN              []string   `proxy:"alpn,omitempty"`
	SNI               string     `proxy:"sni,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`
	ClientFingerprint string     `proxy:"client-fingerprint"`
	SkipCertVerify    bool       `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string     `proxy:"fingerprint,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	Profile           string     `proxy:"profile"`
	ProfileVersion    int        `proxy:"profile-version"`
	UDP               bool       `proxy:"udp,omitempty"`
}

func NewArtX(option ArtXOption) (*ArtX, error) {
	if option.Server == "" || option.Port < 1 || option.Port > 65535 || strings.TrimSpace(option.Password) == "" {
		return nil, errors.New("invalid artx server, port, or password")
	}
	if option.Profile != "balanced" && option.Profile != "web" && option.Profile != "media" && option.Profile != "realtime" {
		return nil, fmt.Errorf("unsupported artx profile: %s", option.Profile)
	}
	if option.ProfileVersion < 1 || option.ProfileVersion > 3 {
		return nil, fmt.Errorf("unsupported artx profile-version: %d", option.ProfileVersion)
	}
	if option.ProfileVersion >= 2 && option.Profile != "balanced" {
		return nil, fmt.Errorf("artx profile-version %d requires the balanced profile", option.ProfileVersion)
	}
	if strings.TrimSpace(option.ClientFingerprint) == "" {
		return nil, errors.New("artx client-fingerprint is required")
	}
	if _, ok := tlsC.GetFingerprint(option.ClientFingerprint); !ok {
		return nil, fmt.Errorf("unsupported artx client-fingerprint: %s", option.ClientFingerprint)
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &ArtX{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.ArtX,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	tlsHost := option.SNI
	if tlsHost == "" {
		tlsHost = option.Server
	}
	outbound.tlsConfig = &vmess.TLSConfig{
		Host: tlsHost, SkipCertVerify: option.SkipCertVerify, NextProtos: option.ALPN,
		FingerPrint: option.Fingerprint, Certificate: option.Certificate, PrivateKey: option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint, ECH: echConfig,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func (artx *ArtX) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	raw, err := artx.dialer.DialContext(ctx, "tcp", artx.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", artx.addr, err)
	}
	defer func() { safeConnClose(raw, err) }()
	destination := artxTransport.Destination{Host: metadata.Host, IP: metadata.DstIP, Port: metadata.DstPort}
	connection, err := artxTransport.DialContext(ctx, raw, artxTransport.ClientConfig{
		Password:       artx.option.Password,
		Profile:        artx.option.Profile,
		ProfileVersion: uint32(artx.option.ProfileVersion),
		TLSConfig:      artx.tlsConfig,
	}, destination)
	if err != nil {
		return nil, err
	}
	return NewConn(connection, artx), nil
}

func (artx *ArtX) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !artx.option.UDP {
		return nil, C.ErrNotSupport
	}
	if err := artx.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	raw, err := artx.dialer.DialContext(ctx, "tcp", artx.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", artx.addr, err)
	}
	defer func() { safeConnClose(raw, err) }()

	destination := artxTransport.Destination{Host: metadata.Host, IP: metadata.DstIP, Port: metadata.DstPort}
	packetConnection, err := artxTransport.DialPacketContext(ctx, raw, artxTransport.ClientConfig{
		Password:       artx.option.Password,
		Profile:        artx.option.Profile,
		ProfileVersion: uint32(artx.option.ProfileVersion),
		TLSConfig:      artx.tlsConfig,
	}, destination, metadata.UDPAddr())
	if err != nil {
		return nil, err
	}
	return newPacketConn(packetConnection, artx), nil
}

func (artx *ArtX) ProxyInfo() C.ProxyInfo {
	info := artx.Base.ProxyInfo()
	info.DialerProxy = artx.option.DialerProxy
	return info
}
