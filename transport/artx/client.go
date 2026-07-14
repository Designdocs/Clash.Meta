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
	earlyRecordPlainSettingsLength   = 24
	earlyRecordGreasedSettingsLength = 30
	earlyRecordPaddingLength         = 14
)

type ClientConfig struct {
	Password       string
	Profile        string
	ProfileVersion uint32
	TLSConfig      *vmess.TLSConfig
}

func DialContext(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination) (connection net.Conn, err error) {
	if raw == nil || config.TLSConfig == nil {
		return nil, errors.New("artx connection and TLS config are required")
	}
	if strings.TrimSpace(config.Password) == "" {
		return nil, errors.New("artx password is required")
	}
	if err := validateClientProfile(config.Profile, config.ProfileVersion); err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.TLSConfig.ClientFingerprint) == "" {
		return nil, errors.New("artx client fingerprint is required")
	}
	if _, ok := tlsC.GetFingerprint(config.TLSConfig.ClientFingerprint); !ok {
		return nil, fmt.Errorf("artx unsupported client fingerprint: %s", config.TLSConfig.ClientFingerprint)
	}
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopContextClose()

	tlsConfig := *config.TLSConfig
	tlsConfig.DisableRenegotiation = true
	tlsConnection, err := vmess.StreamTLSConn(ctx, raw, &tlsConfig)
	if err != nil {
		return nil, err
	}
	state := tlsC.GetTLSConnectionState(tlsConnection)
	if state.Version != tls.VersionTLS13 {
		return nil, errors.New("artx TLS 1.3 is required")
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

	serverSettings, err := readServerSettings(tlsConnection, config.ProfileVersion)
	if err != nil {
		return nil, err
	}
	if err := serverSettings.Validate(config.ProfileVersion); err != nil {
		return nil, err
	}
	if err := WriteFrame(tlsConnection, FrameSettings, 0, DefaultSettings(config.ProfileVersion).MarshalBinary()); err != nil {
		return nil, err
	}
	if err := WriteFrame(tlsConnection, FrameTCPSyn, 1, destination.MarshalBinary()); err != nil {
		return nil, err
	}
	if !stopContextClose() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("artx handshake context ended")
	}
	return NewConn(tlsConnection), nil
}

func readServerSettings(reader net.Conn, profileVersion uint32) (Settings, error) {
	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			return Settings{}, err
		}
		if frame.Type == FrameSettings {
			settings, err := ParseSettings(frame.Payload)
			if err != nil {
				return Settings{}, err
			}
			if err := validateServerSettingsFlight(reader, profileVersion, len(frame.Payload)); err != nil {
				return Settings{}, err
			}
			return settings, nil
		}
		if knownFrame(frame.Type) {
			return Settings{}, errors.New("artx server SETTINGS required before stream frames")
		}
	}
}

func validateServerSettingsFlight(reader net.Conn, profileVersion uint32, settingsLength int) error {
	if profileVersion != earlyRecordProfileVersion {
		return nil
	}
	switch settingsLength {
	case earlyRecordGreasedSettingsLength:
		return nil
	case earlyRecordPlainSettingsLength:
		padding, err := ReadFrame(reader)
		if err != nil {
			return err
		}
		if padding.Type != FramePadding || padding.StreamID != 0 || len(padding.Payload) != earlyRecordPaddingLength {
			return errors.New("artx profile version 2 padding frame is invalid")
		}
		return nil
	default:
		return fmt.Errorf("artx profile version 2 SETTINGS length is %d", settingsLength)
	}
}

func validateClientProfile(profile string, profileVersion uint32) error {
	switch profileVersion {
	case 1:
		return nil
	case earlyRecordProfileVersion:
		if profile != "balanced" {
			return errors.New("artx profile version 2 requires the balanced profile")
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
