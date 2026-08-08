package artx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	lifecycleTraceFDEnvironment = "ARTX_LIFECYCLE_TRACE_FD"
	lifecyclePacketMagic        = "AXM1"
	lifecyclePacketVersion      = byte(1)
	lifecyclePacketHeaderSize   = 52
)

var (
	lifecycleTraceOnce sync.Once
	lifecycleSink      *lifecycleTraceSink
)

type lifecycleTraceEvent struct {
	SchemaVersion  int    `json:"schema_version"`
	Role           string `json:"role"`
	AssociationID  uint64 `json:"association_id"`
	Disposition    string `json:"disposition"`
	Event          string `json:"event"`
	MonotonicNS    int64  `json:"monotonic_ns"`
	SourcePort     uint16 `json:"source_port"`
	TerminalReason string `json:"terminal_reason,omitempty"`
}

type lifecycleTraceSink struct {
	started time.Time
	file    *os.File
	mu      sync.Mutex
	err     error
}

type lifecyclePacketConn struct {
	net.PacketConn
	sink        *lifecycleTraceSink
	sourcePort  uint16
	mu          sync.Mutex
	association uint64
	disposition string
	terminal    bool
}

// ObserveLifecyclePacketConn is inert unless the inherited lifecycle trace
// descriptor is configured before process start.
func ObserveLifecyclePacketConn(connection net.PacketConn, sourcePort uint16) net.PacketConn {
	sink := loadLifecycleTraceSink()
	if sink == nil {
		return connection
	}
	return &lifecyclePacketConn{PacketConn: connection, sink: sink, sourcePort: sourcePort}
}

func loadLifecycleTraceSink() *lifecycleTraceSink {
	lifecycleTraceOnce.Do(func() {
		descriptor, err := strconv.Atoi(os.Getenv(lifecycleTraceFDEnvironment))
		if err != nil || !validLifecycleTraceDescriptor(descriptor) {
			return
		}
		file := os.NewFile(uintptr(descriptor), "artx-lifecycle-trace")
		if file != nil {
			lifecycleSink = &lifecycleTraceSink{started: time.Now(), file: file}
		}
	})
	return lifecycleSink
}

func validLifecycleTraceDescriptor(descriptor int) bool {
	return descriptor == 0 || descriptor >= 3
}

func (connection *lifecyclePacketConn) WriteTo(payload []byte, remote net.Addr) (int, error) {
	association, disposition, observed := parseLifecycleAssociation(payload)
	if observed {
		if err := connection.open(association, disposition); err != nil {
			_ = connection.PacketConn.Close()
			return 0, err
		}
	}
	return connection.PacketConn.WriteTo(payload, remote)
}

func (connection *lifecyclePacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	return connection.PacketConn.ReadFrom(payload)
}

func (connection *lifecyclePacketConn) Close() error {
	closeErr := connection.PacketConn.Close()
	traceErr := connection.finish(reasonForError("close_complete", "close_error", closeErr))
	return errors.Join(closeErr, traceErr)
}

func (connection *lifecyclePacketConn) open(association uint64, disposition string) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.association != 0 {
		if connection.association != association || connection.disposition != disposition {
			return errors.New("artx lifecycle association changed within one packet connection")
		}
		return nil
	}
	event := lifecycleTraceEvent{
		SchemaVersion: 1,
		Role:          "client",
		AssociationID: association,
		Disposition:   disposition,
		Event:         "opened",
		SourcePort:    connection.sourcePort,
	}
	if err := connection.sink.write(event, false); err != nil {
		return err
	}
	connection.association = association
	connection.disposition = disposition
	return nil
}

func (connection *lifecyclePacketConn) finish(reason string) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.association == 0 || connection.terminal {
		return nil
	}
	connection.terminal = true
	return connection.sink.write(lifecycleTraceEvent{
		SchemaVersion:  1,
		Role:           "client",
		AssociationID:  connection.association,
		Disposition:    connection.disposition,
		Event:          "terminal",
		SourcePort:     connection.sourcePort,
		TerminalReason: reason,
	}, true)
}

func (sink *lifecycleTraceSink) write(event lifecycleTraceEvent, syncFile bool) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	event.MonotonicNS = time.Since(sink.started).Nanoseconds()
	sink.err = json.NewEncoder(sink.file).Encode(event)
	if sink.err == nil && syncFile {
		sink.err = sink.file.Sync()
	}
	return sink.err
}

func parseLifecycleAssociation(payload []byte) (uint64, string, bool) {
	if len(payload) < lifecyclePacketHeaderSize ||
		string(payload[:4]) != lifecyclePacketMagic ||
		payload[4] != lifecyclePacketVersion {
		return 0, "", false
	}
	payloadLength := int(binary.BigEndian.Uint16(payload[32:34]))
	if len(payload) != lifecyclePacketHeaderSize+payloadLength ||
		binary.BigEndian.Uint64(payload[16:24]) != 0 {
		return 0, "", false
	}
	payloadHash := sha256.Sum256(payload[lifecyclePacketHeaderSize:])
	if !bytes.Equal(payloadHash[:16], payload[36:52]) {
		return 0, "", false
	}
	disposition := ""
	switch payload[5] {
	case 3:
		disposition = "normal"
	case 4:
		disposition = "cancel"
	default:
		return 0, "", false
	}
	association := binary.BigEndian.Uint64(payload[8:16])
	return association, disposition, association != 0
}

func reasonForError(success, failure string, err error) string {
	if err != nil {
		return failure
	}
	return success
}
