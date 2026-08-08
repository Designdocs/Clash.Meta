package artx

import (
	"errors"
	"io"
	"net"
	"sync"

	N "github.com/metacubex/sing/common/network"
)

const (
	r0PhaseSetup uint8 = 1
)

const (
	r0EventConnectionStart uint8 = 1
	r0EventTLSReady        uint8 = 2
	r0EventClientOpenWrite uint8 = 3
	r0EventProofWait       uint8 = 4
	r0EventProofChecked    uint8 = 5
	r0EventProofVerified   uint8 = 6
	r0EventInnerExposed    uint8 = 7
	r0EventPayloadWrite    uint8 = 8
	r0EventPayloadRead     uint8 = 9
	r0EventClientWriteFIN  uint8 = 10
	r0EventEdgeReadFIN     uint8 = 11
	r0EventConnectionEnd   uint8 = 12
	r0EventQueueOverflow   uint8 = 13
	r0EventWriteStart      uint8 = 14
)

type r0Hook interface {
	ObserveWriter(phase, kind uint8, writer io.Writer) io.Writer
	Event(phase, kind, result uint8)
	IOEvent(phase, kind, result uint8, attempted, accepted int)
	Close()
}

func observeR0Writer(hook r0Hook, phase, kind uint8, writer io.Writer) io.Writer {
	if hook == nil {
		return writer
	}
	return hook.ObserveWriter(phase, kind, writer)
}

func emitR0Event(hook r0Hook, phase, kind, result uint8) {
	if hook != nil {
		hook.Event(phase, kind, result)
	}
}

func closeR0Hook(hook r0Hook) {
	if hook != nil {
		hook.Close()
	}
}

func wrapR0Connection(connection net.Conn, hook r0Hook) net.Conn {
	if hook == nil {
		return connection
	}
	return &r0ObservedConnection{Conn: connection, hook: hook}
}

type r0ObservedConnection struct {
	net.Conn
	hook          r0Hook
	mu            sync.Mutex
	readFIN       bool
	writeFIN      bool
	connectionEnd bool
}

type r0EOFReader struct {
	reader io.Reader
	onEOF  func()
}

func (reader *r0EOFReader) Read(payload []byte) (int, error) {
	read, err := reader.reader.Read(payload)
	if err == io.EOF {
		reader.onEOF()
	}
	return read, err
}

func (connection *r0ObservedConnection) Read(payload []byte) (int, error) {
	read, err := connection.Conn.Read(payload)
	connection.emitIO(r0EventPayloadRead, len(payload), read, err)
	if err == io.EOF {
		connection.emitReadFIN()
	}
	return read, err
}

func (connection *r0ObservedConnection) Write(payload []byte) (int, error) {
	written, err := connection.Conn.Write(payload)
	connection.emitIO(r0EventPayloadWrite, len(payload), written, err)
	return written, err
}

// UnwrapReader and UnwrapWriter retain sing's optimized relay path and
// secret-free accepted-byte counters. The reader keeps one non-copying EOF
// observer because CountFunc reports bytes only and cannot represent FIN.
// Do not expose Upstream: doing so would bypass these callbacks completely.
func (connection *r0ObservedConnection) UnwrapReader() (io.Reader, []N.CountFunc) {
	return &r0EOFReader{reader: connection.Conn, onEOF: connection.emitReadFIN}, []N.CountFunc{func(count int64) {
		connection.hook.IOEvent(r0PhaseSetup, r0EventPayloadRead, 1, int(count), int(count))
	}}
}

func (connection *r0ObservedConnection) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return connection.Conn, []N.CountFunc{func(count int64) {
		connection.hook.IOEvent(r0PhaseSetup, r0EventPayloadWrite, 1, int(count), int(count))
	}}
}

func (connection *r0ObservedConnection) ReaderReplaceable() bool { return true }

func (connection *r0ObservedConnection) WriterReplaceable() bool { return true }

func (connection *r0ObservedConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("artx connection does not support CloseWrite")
	}
	err := closeWriter.CloseWrite()
	result := uint8(1)
	if err != nil {
		result = 2
	}
	connection.mu.Lock()
	if !connection.writeFIN {
		connection.writeFIN = true
		connection.hook.Event(r0PhaseSetup, r0EventClientWriteFIN, result)
	}
	connection.mu.Unlock()
	return err
}

func (connection *r0ObservedConnection) Close() error {
	err := connection.Conn.Close()
	connection.mu.Lock()
	if !connection.connectionEnd {
		connection.connectionEnd = true
		connection.hook.Close()
	}
	connection.mu.Unlock()
	return err
}

func (connection *r0ObservedConnection) emitReadFIN() {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.readFIN {
		return
	}
	connection.readFIN = true
	connection.hook.Event(r0PhaseSetup, r0EventEdgeReadFIN, 1)
}

func (connection *r0ObservedConnection) emitIO(kind uint8, attempted, accepted int, err error) {
	result := uint8(1)
	if err != nil {
		result = 2
	} else if accepted != attempted {
		result = 3
	}
	connection.hook.IOEvent(r0PhaseSetup, kind, result, attempted, accepted)
}
