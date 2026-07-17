package artx

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

const (
	exporterLabel                    = "EXPORTER-artx-auth-v1"
	exporterLength                   = 32
	bucketSeconds                    = int64(60)
	earlyRecordProfileVersion        = uint32(2)
	earlyGapProfileVersion           = uint32(3)
	earlyRecordPlainSettingsLength   = 24
	earlyRecordGreasedSettingsLength = 30
	earlyRecordPaddingLength         = 14
)

type ClientConfig struct {
	Password       string
	Profile        string
	ProfileVersion uint32
	WireVersion    uint32
	Authority      string
	TLSConfig      *vmess.TLSConfig
}

func DialContext(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination) (connection net.Conn, err error) {
	if normalizedWireVersion(config.WireVersion) == 3 {
		return dialWireV3Context(ctx, raw, config, destination)
	}
	connection, err = dialContext(ctx, raw, config, destination, FrameTCPSyn)
	if err != nil {
		return nil, err
	}
	return NewConn(connection), nil
}

func DialPacketContext(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination, remote net.Addr) (*PacketConn, error) {
	if normalizedWireVersion(config.WireVersion) == 3 {
		return nil, errors.New("artx wire-v3 is TCP-only")
	}
	if remote == nil {
		return nil, errors.New("artx UDP remote address is required")
	}
	connection, err := dialContext(ctx, raw, config, destination, FrameUDPAssoc)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(connection, remote), nil
}

func dialContext(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination, openFrame byte) (connection net.Conn, err error) {
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	connection, err = establishSession(ctx, raw, config)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(connection, normalizedWireVersion(config.WireVersion), openFrame, 1, destination.MarshalBinary()); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func establishSession(ctx context.Context, raw net.Conn, config ClientConfig) (connection net.Conn, err error) {
	wireVersion := normalizedWireVersion(config.WireVersion)
	if wireVersion != 1 && wireVersion != 2 {
		return nil, fmt.Errorf("artx unsupported wire version: %d", wireVersion)
	}
	if err := validateClientConfig(raw, config, wireVersion); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopContextClose()

	tlsConnection, state, err := dialArtXTLS(ctx, raw, config, nil)
	if err != nil {
		return nil, err
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLength)
	if err != nil {
		return nil, fmt.Errorf("artx TLS exporter: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	auth, err := BuildAuthFrame([]byte(config.Password), salt, exporter, uint32(time.Now().Unix()/bucketSeconds), nil)
	if err != nil {
		return nil, err
	}
	if err := writeFull(tlsConnection, auth); err != nil {
		return nil, err
	}

	serverSettings, err := readServerSettingsForWire(tlsConnection, wireVersion, config.ProfileVersion)
	if err != nil {
		return nil, err
	}
	if err := serverSettings.validateWire(wireVersion, config.ProfileVersion); err != nil {
		return nil, err
	}
	if err := writeFrame(tlsConnection, wireVersion, FrameSettings, 0, settingsForWire(wireVersion, config.ProfileVersion).MarshalBinary()); err != nil {
		return nil, err
	}
	if !stopContextClose() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("artx handshake context ended")
	}
	return tlsConnection, nil
}

func validateClientConfig(raw net.Conn, config ClientConfig, wireVersion uint32) error {
	if raw == nil || config.TLSConfig == nil {
		return errors.New("artx connection and TLS config are required")
	}
	if strings.TrimSpace(config.Password) == "" {
		return errors.New("artx password is required")
	}
	if err := validateClientProfile(config.Profile, config.ProfileVersion); err != nil {
		return err
	}
	if wireVersion == 3 && (config.Profile != "balanced" || config.ProfileVersion != 1 || strings.TrimSpace(config.Authority) == "") {
		return errors.New("artx wire-v3 requires balanced profile version 1 and authority")
	}
	if strings.TrimSpace(config.TLSConfig.ClientFingerprint) == "" {
		return errors.New("artx client fingerprint is required")
	}
	if _, ok := tlsC.GetFingerprint(config.TLSConfig.ClientFingerprint); !ok {
		return fmt.Errorf("artx unsupported client fingerprint: %s", config.TLSConfig.ClientFingerprint)
	}
	return nil
}

func dialArtXTLS(ctx context.Context, raw net.Conn, config ClientConfig, nextProtos []string) (net.Conn, tls.ConnectionState, error) {
	tlsConfig := *config.TLSConfig
	tlsConfig.DisableRenegotiation = true
	if nextProtos != nil {
		tlsConfig.NextProtos = nextProtos
	}
	connection, err := vmess.StreamTLSConn(ctx, raw, &tlsConfig)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	state := tlsC.GetTLSConnectionState(connection)
	if state.Version != tls.VersionTLS13 {
		_ = connection.Close()
		return nil, tls.ConnectionState{}, errors.New("artx TLS 1.3 is required")
	}
	return connection, state, nil
}

func normalizedWireVersion(wireVersion uint32) uint32 {
	if wireVersion == 0 {
		return 1
	}
	return wireVersion
}

func readServerSettings(reader net.Conn, profileVersion uint32) (Settings, error) {
	return readServerSettingsForWire(reader, 1, profileVersion)
}

func readServerSettingsForWire(reader net.Conn, wireVersion, profileVersion uint32) (Settings, error) {
	for {
		frame, err := readFrame(reader, wireVersion)
		if err != nil {
			return Settings{}, err
		}
		if frame.Type == FrameSettings {
			settings, err := ParseSettings(frame.Payload)
			if err != nil {
				return Settings{}, err
			}
			if err := validateServerSettingsFlight(reader, wireVersion, profileVersion, len(frame.Payload)); err != nil {
				return Settings{}, err
			}
			return settings, nil
		}
		if knownFrame(frame.Type) {
			return Settings{}, errors.New("artx server SETTINGS required before stream frames")
		}
	}
}

func validateServerSettingsFlight(reader net.Conn, wireVersion, profileVersion uint32, settingsLength int) error {
	if profileVersion < earlyRecordProfileVersion || profileVersion > earlyGapProfileVersion {
		return nil
	}
	baseLength := earlyRecordPlainSettingsLength
	if wireVersion == 2 {
		baseLength += 6
	}
	switch settingsLength {
	case baseLength + 6:
		return nil
	case baseLength:
		padding, err := readFrame(reader, wireVersion)
		if err != nil {
			return err
		}
		if padding.Type != FramePadding || padding.StreamID != 0 || len(padding.Payload) != earlyRecordPaddingLength {
			return fmt.Errorf("artx profile version %d padding frame is invalid", profileVersion)
		}
		return nil
	default:
		return fmt.Errorf("artx profile version %d SETTINGS length is %d", profileVersion, settingsLength)
	}
}

func validateClientProfile(profile string, profileVersion uint32) error {
	switch profileVersion {
	case 1:
		return nil
	case earlyRecordProfileVersion, earlyGapProfileVersion:
		if profile != "balanced" {
			return fmt.Errorf("artx profile version %d requires the balanced profile", profileVersion)
		}
		return nil
	default:
		return fmt.Errorf("artx unsupported profile version: %d", profileVersion)
	}
}

func writeFull(writer net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("artx short write")
		}
		payload = payload[written:]
	}
	return nil
}
