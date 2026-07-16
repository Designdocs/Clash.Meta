package artx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	FrameAuth         byte = 0x01
	FrameSettings     byte = 0x02
	FrameTCPSyn       byte = 0x10
	FrameData         byte = 0x11
	FrameFin          byte = 0x12
	FrameRST          byte = 0x13
	FrameWindowUpdate byte = 0x14
	FrameUDPAssoc     byte = 0x15
	FrameDatagram     byte = 0x16
	FramePadding      byte = 0x20
	FramePing         byte = 0x21
	FramePong         byte = 0x22

	MaxDataPayload  = 64 << 10
	MaxFramePayload = 1 << 20
	MaxUDPPayload   = int(^uint16(0))

	InitialStreamWindow     uint32 = 256 << 10
	InitialConnectionWindow uint32 = 1 << 20
)

const (
	settingMaxConcurrentStreams uint16 = 0x0001
	settingInitialStreamWindow  uint16 = 0x0002
	settingInitialConnWindow    uint16 = 0x0003
	settingProfileVersion       uint16 = 0x0005
)

type Frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

func MarshalFrame(frameType byte, streamID uint32, payload []byte) ([]byte, error) {
	if len(payload) > MaxFramePayload || frameType == FrameData && len(payload) > MaxDataPayload {
		return nil, fmt.Errorf("artx frame payload is too large: %d", len(payload))
	}
	if err := validateFrame(frameType, streamID, len(payload)); err != nil {
		return nil, err
	}
	frame := make([]byte, 8+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	length := len(payload)
	frame[5], frame[6], frame[7] = byte(length>>16), byte(length>>8), byte(length)
	copy(frame[8:], payload)
	return frame, nil
}

func WriteFrame(writer io.Writer, frameType byte, streamID uint32, payload []byte) error {
	frame, err := MarshalFrame(frameType, streamID, payload)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		written, writeErr := writer.Write(frame)
		if writeErr != nil {
			return writeErr
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

func ReadFrame(reader io.Reader) (Frame, error) {
	var header [8]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	length := int(header[5])<<16 | int(header[6])<<8 | int(header[7])
	if length > MaxFramePayload || header[0] == FrameData && length > MaxDataPayload {
		return Frame{}, fmt.Errorf("artx frame payload is too large: %d", length)
	}
	if err := validateFrame(header[0], binary.BigEndian.Uint32(header[1:5]), length); err != nil {
		return Frame{}, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Type: header[0], StreamID: binary.BigEndian.Uint32(header[1:5]), Payload: payload}, nil
}

func BuildAuthFrame(psk, salt, exporter []byte, timestampBucket uint32, padding []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("artx password is empty")
	}
	if len(salt) < 16 || len(salt) > 32 {
		return nil, fmt.Errorf("artx salt length must be between 16 and 32, got %d", len(salt))
	}
	if len(exporter) != 32 {
		return nil, fmt.Errorf("artx TLS exporter must be 32 bytes, got %d", len(exporter))
	}
	if len(padding) > 0xffff {
		return nil, fmt.Errorf("artx auth padding is too large: %d", len(padding))
	}

	locatorMAC := hmac.New(sha256.New, psk)
	locatorMAC.Write([]byte("artx-user-locator-v1"))
	locator := locatorMAC.Sum(nil)

	var bucket [4]byte
	binary.BigEndian.PutUint32(bucket[:], timestampBucket)
	tagMAC := hmac.New(sha256.New, psk)
	tagMAC.Write(salt)
	tagMAC.Write(exporter)
	tagMAC.Write(bucket[:])
	tag := tagMAC.Sum(nil)

	frame := make([]byte, 2+len(salt)+8+4+32+2+len(padding))
	frame[0], frame[1] = FrameAuth, byte(len(salt))
	offset := 2
	copy(frame[offset:], salt)
	offset += len(salt)
	copy(frame[offset:], locator[:8])
	offset += 8
	copy(frame[offset:], bucket[:])
	offset += 4
	copy(frame[offset:], tag)
	offset += 32
	binary.BigEndian.PutUint16(frame[offset:offset+2], uint16(len(padding)))
	copy(frame[offset+2:], padding)
	return frame, nil
}

type Settings struct {
	MaxConcurrentStreams    uint32
	InitialStreamWindow     uint32
	InitialConnectionWindow uint32
	ProfileVersion          uint32
}

func DefaultSettings(profileVersion uint32) Settings {
	return Settings{1, InitialStreamWindow, InitialConnectionWindow, profileVersion}
}

func (settings Settings) MarshalBinary() []byte {
	payload := make([]byte, 24)
	settingsEntry(payload[0:6], settingMaxConcurrentStreams, settings.MaxConcurrentStreams)
	settingsEntry(payload[6:12], settingInitialStreamWindow, settings.InitialStreamWindow)
	settingsEntry(payload[12:18], settingInitialConnWindow, settings.InitialConnectionWindow)
	settingsEntry(payload[18:24], settingProfileVersion, settings.ProfileVersion)
	return payload
}

func ParseSettings(payload []byte) (Settings, error) {
	if len(payload)%6 != 0 {
		return Settings{}, errors.New("invalid artx SETTINGS length")
	}
	settings := Settings{}
	for len(payload) > 0 {
		key, value := binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint32(payload[2:6])
		switch key {
		case settingMaxConcurrentStreams:
			settings.MaxConcurrentStreams = value
		case settingInitialStreamWindow:
			settings.InitialStreamWindow = value
		case settingInitialConnWindow:
			settings.InitialConnectionWindow = value
		case settingProfileVersion:
			settings.ProfileVersion = value
		}
		payload = payload[6:]
	}
	return settings, nil
}

func (settings Settings) Validate(profileVersion uint32) error {
	if settings != DefaultSettings(profileVersion) {
		return fmt.Errorf("incompatible artx SETTINGS: %#v", settings)
	}
	return nil
}

func settingsEntry(target []byte, key uint16, value uint32) {
	binary.BigEndian.PutUint16(target[:2], key)
	binary.BigEndian.PutUint32(target[2:6], value)
}

type Destination struct {
	Host string
	IP   netip.Addr
	Port uint16
}

func (destination Destination) Validate() error {
	if destination.Port == 0 {
		return errors.New("artx destination port is empty")
	}
	if destination.Host != "" {
		if len(destination.Host) > 255 {
			return errors.New("artx destination host is too long")
		}
		return nil
	}
	if !destination.IP.IsValid() {
		return errors.New("artx destination is empty")
	}
	return nil
}

func (destination Destination) MarshalBinary() []byte {
	if destination.Validate() != nil {
		return nil
	}
	var payload []byte
	if destination.Host != "" {
		payload = make([]byte, 2+len(destination.Host)+2)
		payload[0], payload[1] = 0x03, byte(len(destination.Host))
		copy(payload[2:], destination.Host)
	} else if destination.IP.Is4() {
		payload = make([]byte, 1+4+2)
		payload[0] = 0x01
		copy(payload[1:], destination.IP.AsSlice())
	} else {
		payload = make([]byte, 1+16+2)
		payload[0] = 0x04
		copy(payload[1:], destination.IP.AsSlice())
	}
	binary.BigEndian.PutUint16(payload[len(payload)-2:], destination.Port)
	return payload
}

func ParseDestination(payload []byte) (Destination, error) {
	if len(payload) < 3 {
		return Destination{}, errors.New("invalid artx destination")
	}
	destination := Destination{}
	switch payload[0] {
	case 0x01:
		if len(payload) != 7 {
			return Destination{}, errors.New("invalid artx IPv4 destination")
		}
		destination.IP = netip.AddrFrom4([4]byte(payload[1:5]))
	case 0x03:
		length := int(payload[1])
		if length == 0 || len(payload) != 2+length+2 {
			return Destination{}, errors.New("invalid artx domain destination")
		}
		destination.Host = string(payload[2 : 2+length])
	case 0x04:
		if len(payload) != 19 {
			return Destination{}, errors.New("invalid artx IPv6 destination")
		}
		destination.IP = netip.AddrFrom16([16]byte(payload[1:17]))
	default:
		return Destination{}, errors.New("invalid artx destination type")
	}
	destination.Port = binary.BigEndian.Uint16(payload[len(payload)-2:])
	return destination, destination.Validate()
}

func MarshalDatagram(payload []byte) ([]byte, error) {
	if len(payload) > MaxUDPPayload {
		return nil, errors.New("artx DATAGRAM payload is too large")
	}
	encoded := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(encoded, uint16(len(payload)))
	copy(encoded[2:], payload)
	return encoded, nil
}

func ParseDatagram(payload []byte) ([]byte, error) {
	if len(payload) < 2 || int(binary.BigEndian.Uint16(payload)) != len(payload)-2 {
		return nil, errors.New("invalid artx DATAGRAM payload length")
	}
	return payload[2:], nil
}

func validateFrame(frameType byte, streamID uint32, payloadLength int) error {
	if frameType == FrameDatagram && payloadLength > MaxUDPPayload+2 {
		return errors.New("artx DATAGRAM payload is too large")
	}
	switch frameType {
	case FrameSettings, FramePadding, FramePing, FramePong:
		if streamID != 0 {
			return errors.New("artx connection frame has a stream ID")
		}
	case FrameTCPSyn, FrameData, FrameFin, FrameRST, FrameUDPAssoc, FrameDatagram:
		if streamID != 1 {
			return errors.New("artx stream frame has an invalid stream ID")
		}
	case FrameWindowUpdate:
		if streamID != 0 && streamID != 1 {
			return errors.New("artx WINDOW_UPDATE has an invalid stream ID")
		}
	}
	switch frameType {
	case FrameFin:
		if payloadLength != 0 {
			return errors.New("artx FIN payload is not empty")
		}
	case FrameRST:
		if payloadLength != 1 {
			return errors.New("artx RST payload must be one byte")
		}
	case FrameWindowUpdate:
		if payloadLength != 4 {
			return errors.New("artx WINDOW_UPDATE payload must be four bytes")
		}
	case FramePing, FramePong:
		if payloadLength != 8 {
			return errors.New("artx PING/PONG payload must be eight bytes")
		}
	}
	return nil
}
