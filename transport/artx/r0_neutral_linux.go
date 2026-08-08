//go:build artxr0 && linux

package artx

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/transport/vmess"
)

const r0NeutralAck byte = 0xa5

// DialR0NeutralContext exercises the ArtX client TLS/fingerprint path without
// sending ArtX authentication, request, target, or payload bytes. It exists
// only in the Linux artxr0 diagnostic build.
func DialR0NeutralContext(ctx context.Context, raw net.Conn, tlsConfig *vmess.TLSConfig, writeSizes []int) (err error) {
	if raw == nil || tlsConfig == nil {
		return errors.New("R0 neutral connection and TLS config are required")
	}
	if !validR0NeutralWriteSizes(writeSizes) {
		return errors.New("R0 neutral write partition is outside the frozen contract")
	}
	hook := newR0Hook(raw)
	defer closeR0Hook(hook)
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()

	config := ClientConfig{TLSConfig: tlsConfig}
	tlsConnection, state, err := dialArtXTLS(ctx, raw, config, []string{"http/1.1"})
	if err != nil {
		return err
	}
	defer tlsConnection.Close()
	emitR0Event(hook, r0PhaseSetup, r0EventTLSReady, 1)
	if state.NegotiatedProtocol != "http/1.1" || state.DidResume {
		return errors.New("R0 neutral control requires fresh TLS with HTTP/1.1 ALPN")
	}

	writer := observeR0Writer(hook, r0PhaseSetup, r0EventClientOpenWrite, tlsConnection)
	for _, size := range writeSizes {
		written, writeErr := writer.Write(make([]byte, size))
		if writeErr != nil {
			return writeErr
		}
		if written != size {
			return fmt.Errorf("R0 neutral short write: %d of %d", written, size)
		}
	}
	emitR0Event(hook, r0PhaseSetup, r0EventProofWait, 1)
	var ack [1]byte
	if _, err := readFull(tlsConnection, ack[:]); err != nil {
		emitR0Event(hook, r0PhaseSetup, r0EventProofChecked, 2)
		return err
	}
	if ack[0] != r0NeutralAck {
		emitR0Event(hook, r0PhaseSetup, r0EventProofChecked, 2)
		return errors.New("R0 neutral acknowledgement mismatch")
	}
	emitR0Event(hook, r0PhaseSetup, r0EventProofChecked, 1)
	emitR0Event(hook, r0PhaseSetup, r0EventProofVerified, 1)
	return nil
}

func validR0NeutralWriteSizes(sizes []int) bool {
	allowed := map[string]bool{
		"64": true, "171": true, "172": true, "173": true,
		"86,86": true, "171,1": true, "1,171": true,
	}
	if len(sizes) == 0 || len(sizes) > 2 {
		return false
	}
	key := fmt.Sprint(sizes[0])
	if len(sizes) == 2 {
		key = fmt.Sprintf("%d,%d", sizes[0], sizes[1])
	}
	return allowed[key]
}

func readFull(reader net.Conn, payload []byte) (int, error) {
	read := 0
	for read < len(payload) {
		count, err := reader.Read(payload[read:])
		read += count
		if err != nil {
			return read, err
		}
		if count == 0 {
			return read, errors.New("R0 neutral short read")
		}
	}
	return read, nil
}
