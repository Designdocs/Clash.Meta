//go:build artxr0 && linux

package artx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	N "github.com/metacubex/sing/common/network"
)

type r0TestWriter struct {
	buffer bytes.Buffer
	writes int
	limit  int
	err    error
}

func TestR0ObservedConnectionUnwrapsWithCountersAndReadFIN(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	hook := &r0RecordingHook{}
	observed := &r0ObservedConnection{Conn: client, hook: hook}
	reader, readCounters := N.UnwrapCountReader(observed, nil)
	writer, writeCounters := N.UnwrapCountWriter(observed, nil)
	eofReader, ok := reader.(*r0EOFReader)
	if !ok || eofReader.reader != client {
		t.Fatalf("optimized reader = %T, want one EOF observer around the original connection", reader)
	}
	if writer != client {
		t.Fatal("diagnostic wrapper changed the optimized writer endpoint")
	}
	if len(readCounters) != 1 || len(writeCounters) != 1 {
		t.Fatalf("counter count = read %d write %d", len(readCounters), len(writeCounters))
	}
	readCounters[0](7)
	writeCounters[0](11)
	if got := hook.accepted(r0EventPayloadRead); got != 7 {
		t.Fatalf("read count = %d", got)
	}
	if got := hook.accepted(r0EventPayloadWrite); got != 11 {
		t.Fatalf("write count = %d", got)
	}

	go func() {
		_, _ = server.Write([]byte("response"))
		_ = server.Close()
	}()
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "response" {
		t.Fatalf("read payload = %q", payload)
	}
	if got := hook.count(r0EventEdgeReadFIN); got != 1 {
		t.Fatalf("read FIN events = %d, want 1", got)
	}
	_, _ = reader.Read(make([]byte, 1))
	if got := hook.count(r0EventEdgeReadFIN); got != 1 {
		t.Fatalf("read FIN events after repeated EOF = %d, want 1", got)
	}
}

func TestR0EventSinkRecordsQueueOverflowOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.csv")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sink := &r0EventSink{queue: make(chan r0WireEvent, 1), file: file}
	sink.queue <- r0WireEvent{}
	previous := r0Sink
	r0Sink = sink
	defer func() { r0Sink = previous }()
	client, server := net.Pipe()
	defer server.Close()
	hook := &r0HookSession{raw: client, connection: 1}
	hook.emit(r0PhaseSetup, r0EventPayloadWrite, 1, 0, 1, 1)
	hook.emit(r0PhaseSetup, r0EventPayloadWrite, 1, 0, 1, 1)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(content), ",13,") != 1 {
		t.Fatalf("overflow records = %q", content)
	}
	if !sink.failed.Load() {
		t.Fatal("overflow did not latch sink failure")
	}
}

func TestR0HookSerializesEventsAndClosesLast(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	sink := &r0EventSink{queue: make(chan r0WireEvent, 64)}
	previous := r0Sink
	r0Sink = sink
	defer func() { r0Sink = previous }()
	hook := &r0HookSession{raw: client, connection: 9}
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			hook.emit(r0PhaseSetup, r0EventPayloadWrite, 1, 0, 1, 1)
		}()
	}
	workers.Wait()
	hook.Close()
	hook.emit(r0PhaseSetup, r0EventPayloadWrite, 1, 0, 1, 1)
	if got := len(sink.queue); got != 33 {
		t.Fatalf("queued events = %d, want 33", got)
	}
	for wantSequence := uint64(1); wantSequence <= 33; wantSequence++ {
		event := <-sink.queue
		if event.Sequence != wantSequence {
			t.Fatalf("event sequence = %d, want %d", event.Sequence, wantSequence)
		}
		if wantSequence == 33 && event.Kind != r0EventConnectionEnd {
			t.Fatalf("final event kind = %d, want connection end", event.Kind)
		}
	}
}

type r0RecordingHook struct {
	events []r0RecordedIO
}

type r0RecordedIO struct {
	kind     uint8
	accepted int
}

func (hook *r0RecordingHook) ObserveWriter(uint8, uint8, io.Writer) io.Writer { panic("unused") }
func (hook *r0RecordingHook) Event(_ uint8, kind uint8, _ uint8) {
	hook.events = append(hook.events, r0RecordedIO{kind: kind})
}
func (hook *r0RecordingHook) Close() {}
func (hook *r0RecordingHook) IOEvent(_ uint8, kind, _ uint8, _, accepted int) {
	hook.events = append(hook.events, r0RecordedIO{kind: kind, accepted: accepted})
}
func (hook *r0RecordingHook) accepted(kind uint8) int {
	total := 0
	for _, event := range hook.events {
		if event.kind == kind {
			total += event.accepted
		}
	}
	return total
}

func (hook *r0RecordingHook) count(kind uint8) int {
	total := 0
	for _, event := range hook.events {
		if event.kind == kind {
			total++
		}
	}
	return total
}

func (writer *r0TestWriter) Write(payload []byte) (int, error) {
	writer.writes++
	accepted := len(payload)
	if writer.limit > 0 && accepted > writer.limit {
		accepted = writer.limit
	}
	_, _ = writer.buffer.Write(payload[:accepted])
	return accepted, writer.err
}

func TestR0CountingWriterIsByteTransparent(t *testing.T) {
	tests := []struct {
		name   string
		limit  int
		err    error
		result uint8
	}{
		{name: "complete", result: 1},
		{name: "short", limit: 2, result: 3},
		{name: "error", err: errors.New("write failed"), result: 2},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			underlying := &r0TestWriter{limit: testCase.limit, err: testCase.err}
			var attempted, written int
			var result uint8
			observer := &r0CountingWriter{
				writer:    underlying,
				nextIndex: func() uint64 { return 7 },
				begin: func(gotAttempted int, writeIndex uint64) {
					if gotAttempted != len([]byte("secret-free-boundary")) || writeIndex != 7 {
						t.Fatalf("write start = bytes %d index %d", gotAttempted, writeIndex)
					}
				},
				emit: func(gotAttempted, gotWritten int, gotResult uint8, writeIndex uint64) {
					attempted, written, result = gotAttempted, gotWritten, gotResult
					if writeIndex != 7 {
						t.Fatalf("write index = %d, want 7", writeIndex)
					}
				},
			}
			payload := []byte("secret-free-boundary")
			gotWritten, gotErr := observer.Write(payload)
			if underlying.writes != 1 {
				t.Fatalf("underlying writes = %d, want 1", underlying.writes)
			}
			if gotWritten != written || !errors.Is(gotErr, testCase.err) {
				t.Fatalf("Write = (%d, %v), observed (%d, %v)", gotWritten, gotErr, written, testCase.err)
			}
			if attempted != len(payload) || result != testCase.result {
				t.Fatalf("event = attempted %d result %d", attempted, result)
			}
			if !bytes.Equal(underlying.buffer.Bytes(), payload[:written]) {
				t.Fatal("observer changed accepted bytes")
			}
		})
	}
}
