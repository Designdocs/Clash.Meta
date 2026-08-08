package naive

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// buildFrame assembles a padded frame by hand so the reader is checked against
// the documented layout rather than against this package's own writer.
func buildFrame(payload []byte, paddingSize int) []byte {
	frame := make([]byte, paddedFrameHeaderSize)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	frame[2] = byte(paddingSize)
	frame = append(frame, payload...)
	return append(frame, make([]byte, paddingSize)...)
}

func TestGenerateHeaderPaddingShape(t *testing.T) {
	lengths := make(map[int]bool)
	for sample := 0; sample < 512; sample++ {
		padding := generateHeaderPadding()
		if len(padding) < minHeaderPaddingSize || len(padding) > maxHeaderPaddingSize {
			t.Fatalf("padding length %d is outside [%d, %d]", len(padding), minHeaderPaddingSize, maxHeaderPaddingSize)
		}
		lengths[len(padding)] = true
		for i := 0; i < len(padding); i++ {
			if i < len(paddingHeaderSymbols) {
				if !strings.ContainsRune(paddingHeaderSymbols, rune(padding[i])) {
					t.Fatalf("padding[%d] = %q is outside the symbol set", i, padding[i])
				}
				continue
			}
			if padding[i] != '~' {
				t.Fatalf("padding[%d] = %q, want '~'", i, padding[i])
			}
		}
	}
	if len(lengths) < 2 {
		t.Fatalf("padding length never varied across 512 samples: %v", lengths)
	}
}

func TestWritePaddedFrameWireFormat(t *testing.T) {
	payload := []byte("hello naive")
	var wire bytes.Buffer
	state := newPaddingState(true)
	if err := state.writePaddedFrame(&wire, payload); err != nil {
		t.Fatal(err)
	}

	frame := wire.Bytes()
	if len(frame) < paddedFrameHeaderSize {
		t.Fatalf("frame is %d bytes, shorter than its header", len(frame))
	}
	if size := int(binary.BigEndian.Uint16(frame[:2])); size != len(payload) {
		t.Fatalf("header payload size is %d, want %d", size, len(payload))
	}
	paddingSize := int(frame[2])
	if want := paddedFrameHeaderSize + len(payload) + paddingSize; len(frame) != want {
		t.Fatalf("frame is %d bytes, want %d", len(frame), want)
	}
	if body := frame[paddedFrameHeaderSize : paddedFrameHeaderSize+len(payload)]; !bytes.Equal(body, payload) {
		t.Fatalf("frame payload is %q, want %q", body, payload)
	}
	for i, b := range frame[paddedFrameHeaderSize+len(payload):] {
		if b != 0 {
			t.Fatalf("padding byte %d is %#x, want zero", i, b)
		}
	}
	if state.framesWritten != 1 {
		t.Fatalf("framesWritten is %d, want 1", state.framesWritten)
	}
}

func TestReadWithPaddingParsesHandBuiltFrames(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(buildFrame([]byte("first"), 7))
	wire.Write(buildFrame([]byte("second"), 0))
	wire.Write(buildFrame([]byte("third"), maxFramePaddingSize))

	state := newPaddingState(true)
	for _, want := range []string{"first", "second", "third"} {
		payload := make([]byte, 64)
		read, err := state.readWithPadding(&wire, payload)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(payload[:read]); got != want {
			t.Fatalf("read %q, want %q", got, want)
		}
	}
	if state.framesRead != 3 {
		t.Fatalf("framesRead is %d, want 3", state.framesRead)
	}
}

func TestReadWithPaddingDrainsPaddingOnlyFrame(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(buildFrame(nil, 32))
	wire.Write(buildFrame([]byte("payload"), 4))

	state := newPaddingState(true)
	payload := make([]byte, 64)
	read, err := state.readWithPadding(&wire, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payload[:read]); got != "payload" {
		t.Fatalf("read %q, want %q", got, "payload")
	}
	if state.framesRead != 2 {
		t.Fatalf("framesRead is %d, want 2 padding-only frames counted", state.framesRead)
	}
}

func TestReadWithPaddingSpansShortBuffers(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 16)
	var wire bytes.Buffer
	wire.Write(buildFrame(payload, 9))
	wire.Write(buildFrame([]byte("tail"), 0))

	state := newPaddingState(true)
	var assembled bytes.Buffer
	chunk := make([]byte, 13)
	for assembled.Len() < len(payload)+len("tail") {
		read, err := state.readWithPadding(&wire, chunk)
		if err != nil {
			t.Fatal(err)
		}
		assembled.Write(chunk[:read])
	}
	if want := string(payload) + "tail"; assembled.String() != want {
		t.Fatalf("reassembled %q, want %q", assembled.String(), want)
	}
}

func TestPaddingStopsAfterTheOpeningFrames(t *testing.T) {
	var wire bytes.Buffer
	state := newPaddingState(true)
	for frame := 0; frame < paddedFrameCount; frame++ {
		if _, err := state.writeWithPadding(&wire, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	framedLength := wire.Len()
	if framedLength <= paddedFrameCount {
		t.Fatalf("padded writes produced %d bytes, expected headers and padding", framedLength)
	}

	wire.Reset()
	if _, err := state.writeWithPadding(&wire, []byte("verbatim")); err != nil {
		t.Fatal(err)
	}
	if wire.String() != "verbatim" {
		t.Fatalf("write %d produced %q, want the payload verbatim", paddedFrameCount+1, wire.String())
	}
}

func TestWriteSplitsOversizePayload(t *testing.T) {
	payload := bytes.Repeat([]byte{'z'}, maxPaddedPayloadSize+1024)
	var wire bytes.Buffer
	state := newPaddingState(true)
	written, err := state.writeWithPadding(&wire, payload)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(payload) {
		t.Fatalf("reported %d bytes written, want %d", written, len(payload))
	}
	if state.framesWritten != 2 {
		t.Fatalf("framesWritten is %d, want 2", state.framesWritten)
	}

	reader := newPaddingState(true)
	var assembled bytes.Buffer
	chunk := make([]byte, 4096)
	for assembled.Len() < len(payload) {
		read, err := reader.readWithPadding(&wire, chunk)
		if err != nil {
			t.Fatal(err)
		}
		assembled.Write(chunk[:read])
	}
	if !bytes.Equal(assembled.Bytes(), payload) {
		t.Fatal("payload did not survive the split into frames")
	}
}

func TestDisabledPaddingIsPassThrough(t *testing.T) {
	var wire bytes.Buffer
	state := newPaddingState(false)
	if _, err := state.writeWithPadding(&wire, []byte("plain")); err != nil {
		t.Fatal(err)
	}
	if wire.String() != "plain" {
		t.Fatalf("wrote %q, want %q", wire.String(), "plain")
	}

	payload := make([]byte, 16)
	read, err := state.readWithPadding(strings.NewReader("plain"), payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payload[:read]); got != "plain" {
		t.Fatalf("read %q, want %q", got, "plain")
	}
}

func TestWriteWithPaddingIgnoresEmptyPayload(t *testing.T) {
	var wire bytes.Buffer
	state := newPaddingState(true)
	written, err := state.writeWithPadding(&wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || wire.Len() != 0 {
		t.Fatalf("empty write produced %d bytes on the wire", wire.Len())
	}
	if state.framesWritten != 0 {
		t.Fatalf("empty write consumed frame %d of the padding budget", state.framesWritten)
	}
}

func TestReadWithPaddingReportsTruncatedFrame(t *testing.T) {
	truncated := buildFrame([]byte("payload"), 0)[:2]
	state := newPaddingState(true)
	if _, err := state.readWithPadding(bytes.NewReader(truncated), make([]byte, 16)); err == nil {
		t.Fatal("a truncated frame header must surface an error")
	} else if err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v, want %v", err, io.ErrUnexpectedEOF)
	}
}
