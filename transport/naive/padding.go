// Package naive speaks the client half of the NaiveProxy tunnel: an HTTP/2
// CONNECT request carried over TLS, wrapped in the padding scheme that
// klzgrad/naiveproxy applies to the opening frames of every stream.
package naive

import (
	"encoding/binary"
	"io"

	"github.com/metacubex/mihomo/common/buf"

	"github.com/metacubex/randv2"
)

const (
	// paddedFrameCount mirrors naiveproxy's kFirstPaddings: only the first
	// eight frames of each direction carry padding, after which the stream is
	// forwarded verbatim.
	paddedFrameCount = 8
	// paddedFrameHeaderSize covers a big-endian uint16 payload length followed
	// by one byte of padding length.
	paddedFrameHeaderSize = 3
	// maxPaddedPayloadSize is the largest payload a single frame header can
	// describe; longer writes are split across frames.
	maxPaddedPayloadSize = 0xFFFF
	// maxFramePaddingSize is the longest padding run a frame header can
	// describe.
	maxFramePaddingSize = 0xFF
)

// paddingHeaderSymbols are the characters naiveproxy draws its header padding
// from. None of them sit in HPACK's static table and they compress poorly
// under Huffman coding, so the padding keeps its length on the wire.
const paddingHeaderSymbols = "!#$()+<>?@[]^`{}"

const (
	minHeaderPaddingSize = 16
	maxHeaderPaddingSize = 32
)

// generateHeaderPadding builds the `Padding` request header value. naiveproxy
// draws the leading symbols from paddingHeaderSymbols and fills the rest with
// a '~' run, so a server that inspects the header sees the shape it expects.
func generateHeaderPadding() string {
	padding := make([]byte, minHeaderPaddingSize+randv2.IntN(maxHeaderPaddingSize-minHeaderPaddingSize+1))
	for i := range padding {
		if i < len(paddingHeaderSymbols) {
			padding[i] = paddingHeaderSymbols[randv2.IntN(len(paddingHeaderSymbols))]
			continue
		}
		padding[i] = '~'
	}
	return string(padding)
}

// paddingState tracks how many padded frames each direction of one tunnel has
// left to send or expect, plus how much of the frame currently being read is
// still outstanding. Read and write fields are disjoint, so one reader and one
// writer may run concurrently as net.Conn allows.
type paddingState struct {
	framesRead       int
	framesWritten    int
	payloadRemaining int
	paddingRemaining int
}

// newPaddingState reports a state that pads when the server accepted padding,
// and one that forwards verbatim when it did not.
func newPaddingState(negotiated bool) paddingState {
	if negotiated {
		return paddingState{}
	}
	return paddingState{framesRead: paddedFrameCount, framesWritten: paddedFrameCount}
}

// readWithPadding fills payload from the next frame, consuming frame headers
// and discarding padding runs until real payload turns up or reader fails.
func (state *paddingState) readWithPadding(reader io.Reader, payload []byte) (int, error) {
	for {
		if state.payloadRemaining > 0 {
			if len(payload) > state.payloadRemaining {
				payload = payload[:state.payloadRemaining]
			}
			read, err := reader.Read(payload)
			state.payloadRemaining -= read
			return read, err
		}
		if state.paddingRemaining > 0 {
			skipped, err := io.CopyN(io.Discard, reader, int64(state.paddingRemaining))
			state.paddingRemaining -= int(skipped)
			if err != nil {
				return 0, err
			}
		}
		if state.framesRead >= paddedFrameCount {
			return reader.Read(payload)
		}
		var header [paddedFrameHeaderSize]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return 0, err
		}
		state.framesRead++
		state.payloadRemaining = int(binary.BigEndian.Uint16(header[:2]))
		state.paddingRemaining = int(header[2])
		// A frame may be padding only. Loop instead of returning a zero-length
		// read, which callers would read as a closed stream.
	}
}

// writeWithPadding sends payload as padded frames while any of the opening
// frames remain, then hands the rest to writer untouched.
func (state *paddingState) writeWithPadding(writer io.Writer, payload []byte) (int, error) {
	if state.framesWritten >= paddedFrameCount {
		return writer.Write(payload)
	}
	written := 0
	for len(payload) > 0 {
		if state.framesWritten >= paddedFrameCount {
			remaining, err := writer.Write(payload)
			return written + remaining, err
		}
		chunk := payload
		if len(chunk) > maxPaddedPayloadSize {
			chunk = chunk[:maxPaddedPayloadSize]
		}
		if err := state.writePaddedFrame(writer, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		payload = payload[len(chunk):]
	}
	return written, nil
}

// writePaddedFrame emits one frame in a single write, so the header, payload
// and padding never land in separate HTTP/2 DATA frames.
func (state *paddingState) writePaddedFrame(writer io.Writer, chunk []byte) error {
	paddingSize := randv2.IntN(maxFramePaddingSize + 1)
	frame := buf.NewSize(paddedFrameHeaderSize + len(chunk) + paddingSize)
	defer frame.Release()

	header := frame.Extend(paddedFrameHeaderSize)
	binary.BigEndian.PutUint16(header[:2], uint16(len(chunk)))
	header[2] = byte(paddingSize)
	if _, err := frame.Write(chunk); err != nil {
		return err
	}
	if err := frame.WriteZeroN(paddingSize); err != nil {
		return err
	}
	if _, err := writer.Write(frame.Bytes()); err != nil {
		return err
	}
	state.framesWritten++
	return nil
}
