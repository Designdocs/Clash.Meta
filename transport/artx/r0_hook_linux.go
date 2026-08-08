//go:build artxr0 && linux

package artx

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	r0SchemaVersion = 2
	r0ClientRole    = 1
	r0QueueCapacity = 4096
)

var (
	r0StartedAt    = time.Now()
	r0ConnectionID atomic.Uint64
	r0SinkOnce     sync.Once
	r0Sink         *r0EventSink
)

type r0EventSink struct {
	queue  chan r0WireEvent
	file   *os.File
	mu     sync.Mutex
	failed atomic.Bool
}

type r0WireEvent struct {
	Schema          uint8
	Role            uint8
	Kind            uint8
	Phase           uint8
	Result          uint8
	TCPInfoValid    uint8
	Connection      uint64
	Sequence        uint64
	MonotonicNS     int64
	WallUnixNS      int64
	WriteIndex      uint64
	AttemptedBytes  uint64
	WrittenBytes    uint64
	TotalRetrans    uint32
	BytesRetrans    uint64
	SegmentsOut     uint32
	DataSegmentsOut uint32
}

type r0HookSession struct {
	raw        net.Conn
	mu         sync.Mutex
	connection uint64
	sequence   uint64
	writeIndex uint64
	closed     bool
}

func newR0Hook(connection net.Conn) r0Hook {
	sink := loadR0Sink()
	if sink == nil {
		return nil
	}
	if sink.failed.Load() {
		_ = connection.Close()
		return nil
	}
	hook := &r0HookSession{raw: connection, connection: r0ConnectionID.Add(1)}
	hook.Event(r0PhaseSetup, r0EventConnectionStart, 1)
	return hook
}

func loadR0Sink() *r0EventSink {
	r0SinkOnce.Do(func() {
		descriptor, err := strconv.Atoi(os.Getenv("ARTX_R0_TRACE_FD"))
		if err != nil || descriptor < 3 {
			return
		}
		file := os.NewFile(uintptr(descriptor), "artx-r0-trace")
		if file == nil {
			return
		}
		r0Sink = &r0EventSink{queue: make(chan r0WireEvent, r0QueueCapacity), file: file}
		go func() {
			for event := range r0Sink.queue {
				if err := r0Sink.write(event, false); err != nil {
					r0Sink.failed.Store(true)
				}
			}
		}()
	})
	return r0Sink
}

func (sink *r0EventSink) write(event r0WireEvent, syncFile bool) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if _, err := fmt.Fprintf(sink.file,
		"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
		event.Schema, event.Role, event.Kind, event.Phase, event.Result, event.TCPInfoValid,
		event.Connection, event.Sequence, event.MonotonicNS, event.WallUnixNS, event.WriteIndex,
		event.AttemptedBytes, event.WrittenBytes, event.TotalRetrans, event.BytesRetrans,
		event.SegmentsOut, event.DataSegmentsOut); err != nil {
		return err
	}
	if syncFile {
		return sink.file.Sync()
	}
	return nil
}

func (hook *r0HookSession) ObserveWriter(phase, kind uint8, writer io.Writer) io.Writer {
	return &r0CountingWriter{
		writer: writer,
		begin: func(attempted int, writeIndex uint64) {
			hook.emit(phase, r0EventWriteStart, 1, writeIndex, attempted, 0)
		},
		emit: func(attempted, written int, result uint8, writeIndex uint64) {
			hook.emit(phase, kind, result, writeIndex, attempted, written)
		},
		nextIndex: func() uint64 {
			hook.mu.Lock()
			defer hook.mu.Unlock()
			hook.writeIndex++
			return hook.writeIndex
		},
	}
}

func (hook *r0HookSession) Event(phase, kind, result uint8) {
	hook.emit(phase, kind, result, 0, 0, 0)
}

func (hook *r0HookSession) IOEvent(phase, kind, result uint8, attempted, accepted int) {
	hook.emit(phase, kind, result, 0, attempted, accepted)
}

func (hook *r0HookSession) Close() {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if hook.closed {
		return
	}
	hook.closed = true
	hook.emitLocked(r0PhaseSetup, r0EventConnectionEnd, 1, 0, 0, 0)
}

func (hook *r0HookSession) emit(phase, kind, result uint8, writeIndex uint64, attempted, written int) {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if hook.closed {
		return
	}
	hook.emitLocked(phase, kind, result, writeIndex, attempted, written)
}

func (hook *r0HookSession) emitLocked(phase, kind, result uint8, writeIndex uint64, attempted, written int) {
	now := time.Now()
	hook.sequence++
	event := r0WireEvent{
		Schema: r0SchemaVersion, Role: r0ClientRole, Kind: kind, Phase: phase, Result: result,
		Connection: hook.connection, Sequence: hook.sequence, MonotonicNS: time.Since(r0StartedAt).Nanoseconds(), WallUnixNS: now.UnixNano(),
		WriteIndex: writeIndex, AttemptedBytes: uint64(attempted), WrittenBytes: uint64(written),
	}
	if info, ok := sampleR0CandidateTCPInfo(hook.raw); ok {
		event.TCPInfoValid = 1
		event.TotalRetrans = info.Total_retrans
		event.BytesRetrans = info.Bytes_retrans
		event.SegmentsOut = info.Segs_out
		event.DataSegmentsOut = info.Data_segs_out
	}
	if sink := r0Sink; sink != nil {
		select {
		case sink.queue <- event:
		default:
			if sink.failed.CompareAndSwap(false, true) {
				overflow := event
				overflow.Kind = r0EventQueueOverflow
				overflow.Result = 2
				overflow.WriteIndex = 0
				overflow.AttemptedBytes = 0
				overflow.WrittenBytes = 0
				_ = sink.write(overflow, true)
			}
			_ = hook.raw.Close()
		}
	}
}

type r0CountingWriter struct {
	writer    io.Writer
	begin     func(attempted int, writeIndex uint64)
	emit      func(attempted, written int, result uint8, writeIndex uint64)
	nextIndex func() uint64
}

func (writer *r0CountingWriter) Write(payload []byte) (int, error) {
	index := writer.nextIndex()
	writer.begin(len(payload), index)
	written, err := writer.writer.Write(payload)
	result := uint8(1)
	if err != nil {
		result = 2
	} else if written != len(payload) {
		result = 3
	}
	writer.emit(len(payload), written, result, index)
	return written, err
}

func sampleR0CandidateTCPInfo(connection net.Conn) (*unix.TCPInfo, bool) {
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return nil, false
	}
	rawConnection, err := syscallConnection.SyscallConn()
	if err != nil {
		return nil, false
	}
	var info *unix.TCPInfo
	controlErr := rawConnection.Control(func(descriptor uintptr) {
		info, _ = unix.GetsockoptTCPInfo(int(descriptor), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	return info, controlErr == nil && info != nil
}
