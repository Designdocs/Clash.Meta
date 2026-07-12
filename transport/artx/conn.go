package artx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var errStreamReset = errors.New("artx stream reset")

type Conn struct {
	net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	reader      *receiveBuffer
	frames      lockedFrameWriter
	windows     *sendWindow
	receive     *receiveWindow
	control     chan controlWrite
	updateMu    sync.Mutex
	update      uint32
	updateWake  chan struct{}
	readDone    chan struct{}
	controlDone chan struct{}
	writeMu     sync.Mutex
	writeDone   bool
	closeOnce   sync.Once
	peerFin     bool
	peerFinMu   sync.Mutex
}

func NewConn(connection net.Conn) *Conn {
	connectionContext, cancel := context.WithCancel(context.Background())
	artxConnection := &Conn{
		Conn: connection, ctx: connectionContext, cancel: cancel,
		reader: newReceiveBuffer(InitialStreamWindow),
		frames: lockedFrameWriter{writer: connection}, windows: newSendWindow(), receive: newReceiveWindow(),
		control: make(chan controlWrite, 4), updateWake: make(chan struct{}, 1),
		readDone: make(chan struct{}), controlDone: make(chan struct{}),
	}
	go artxConnection.controlLoop()
	go artxConnection.readLoop()
	return artxConnection
}

func (connection *Conn) Read(payload []byte) (int, error) {
	read, err := connection.reader.read(payload)
	if read > 0 && !connection.peerFinished() {
		if updateErr := connection.replenish(uint32(read)); updateErr != nil && err == nil {
			err = updateErr
		}
	}
	return read, err
}

func (connection *Conn) Write(payload []byte) (int, error) {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.writeDone {
		return 0, net.ErrClosed
	}
	written := 0
	for len(payload) > 0 {
		chunkLength := len(payload)
		if chunkLength > MaxDataPayload {
			chunkLength = MaxDataPayload
		}
		if err := connection.windows.waitConsume(connection.ctx, chunkLength); err != nil {
			return written, err
		}
		if err := connection.frames.write(FrameData, 1, payload[:chunkLength]); err != nil {
			connection.terminate(err)
			return written, err
		}
		written += chunkLength
		payload = payload[chunkLength:]
	}
	return written, nil
}

func (connection *Conn) CloseWrite() (err error) {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.writeDone {
		return nil
	}
	connection.writeDone = true
	return connection.frames.write(FrameFin, 1, nil)
}

func (connection *Conn) Close() error {
	connection.cancel()
	connection.reader.abort(net.ErrClosed)
	var closeErr error
	connection.closeOnce.Do(func() {
		closeErr = connection.Conn.Close()
	})
	return closeErr
}

func (connection *Conn) readLoop() {
	defer close(connection.readDone)
	for {
		frame, err := ReadFrame(connection.Conn)
		if err != nil {
			if connection.peerFinished() {
				connection.finishAfterPeerFIN()
				return
			}
			connection.abort(err)
			return
		}
		switch frame.Type {
		case FrameData:
			if connection.peerFinished() {
				connection.abort(errors.New("artx DATA after FIN"))
				return
			}
			if err := connection.receive.consume(len(frame.Payload)); err != nil {
				connection.abort(err)
				return
			}
			if err := connection.reader.write(frame.Payload); err != nil {
				connection.abort(err)
				return
			}
		case FrameFin:
			connection.peerFinMu.Lock()
			if connection.peerFin {
				connection.peerFinMu.Unlock()
				connection.abort(errors.New("artx duplicate FIN"))
				return
			}
			connection.peerFin = true
			connection.peerFinMu.Unlock()
			connection.reader.close(io.EOF)
		case FrameRST:
			connection.abort(errStreamReset)
			return
		case FrameWindowUpdate:
			increment := binary.BigEndian.Uint32(frame.Payload)
			if increment == 0 {
				connection.abort(errors.New("artx zero WINDOW_UPDATE"))
				return
			}
			if err := connection.windows.update(frame.StreamID, increment); err != nil {
				connection.abort(err)
				return
			}
		case FramePadding, FramePong:
		case FramePing:
			if err := connection.queueControl(controlWrite{frameType: FramePong, payload: frame.Payload}); err != nil {
				connection.abort(err)
				return
			}
		default:
			if knownFrame(frame.Type) {
				connection.abort(errors.New("artx unexpected known frame after stream open"))
				return
			}
			// Unknown frames are ignored for forward compatibility.
		}
	}
}

func (connection *Conn) replenish(increment uint32) error {
	if err := connection.receive.restore(increment); err != nil {
		return err
	}
	connection.updateMu.Lock()
	if increment > ^uint32(0)-connection.update {
		connection.updateMu.Unlock()
		return errors.New("artx pending WINDOW_UPDATE overflow")
	}
	connection.update += increment
	connection.updateMu.Unlock()
	select {
	case connection.updateWake <- struct{}{}:
	default:
	}
	return nil
}

type controlWrite struct {
	frameType byte
	payload   []byte
}

func (connection *Conn) queueControl(control controlWrite) error {
	select {
	case connection.control <- control:
		return nil
	case <-connection.ctx.Done():
		return connection.ctx.Err()
	}
}

func (connection *Conn) controlLoop() {
	defer close(connection.controlDone)
	for {
		select {
		case <-connection.ctx.Done():
			return
		case <-connection.updateWake:
			connection.updateMu.Lock()
			increment := connection.update
			connection.update = 0
			connection.updateMu.Unlock()
			if increment == 0 {
				continue
			}
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, increment)
			if err := connection.frames.write(FrameWindowUpdate, 0, payload); err != nil {
				connection.terminate(err)
				return
			}
			if err := connection.frames.write(FrameWindowUpdate, 1, payload); err != nil {
				connection.terminate(err)
				return
			}
		case control := <-connection.control:
			if err := connection.frames.write(control.frameType, 0, control.payload); err != nil {
				connection.terminate(err)
				return
			}
		}
	}
}

func (connection *Conn) peerFinished() bool {
	connection.peerFinMu.Lock()
	defer connection.peerFinMu.Unlock()
	return connection.peerFin
}

func (connection *Conn) abort(err error) {
	connection.closeOnce.Do(func() {
		connection.cancel()
		connection.reader.abort(err)
		_ = connection.Conn.Close()
	})
}

func (connection *Conn) terminate(err error) {
	if connection.peerFinished() {
		connection.finishAfterPeerFIN()
		return
	}
	// Only the frame reader can distinguish a valid FIN from an abrupt transport
	// failure. Wake it without discarding bytes that may already contain FIN.
	_ = connection.Conn.SetReadDeadline(time.Now())
}

func (connection *Conn) finishAfterPeerFIN() {
	connection.closeOnce.Do(func() {
		connection.cancel()
		connection.reader.close(io.EOF)
		_ = connection.Conn.Close()
	})
}

type lockedFrameWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *lockedFrameWriter) write(frameType byte, streamID uint32, payload []byte) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return WriteFrame(writer.writer, frameType, streamID, payload)
}

type sendWindow struct {
	mu         sync.Mutex
	stream     uint32
	connection uint32
	changed    chan struct{}
	deadline   time.Time
}

func newSendWindow() *sendWindow {
	return &sendWindow{stream: InitialStreamWindow, connection: InitialConnectionWindow, changed: make(chan struct{})}
}

func (window *sendWindow) waitConsume(ctx context.Context, amount int) error {
	for {
		window.mu.Lock()
		if amount >= 0 && uint32(amount) <= window.stream && uint32(amount) <= window.connection {
			window.stream -= uint32(amount)
			window.connection -= uint32(amount)
			window.mu.Unlock()
			return nil
		}
		changed := window.changed
		deadline := window.deadline
		window.mu.Unlock()
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(remaining)
			select {
			case <-ctx.Done():
				stopTimer(timer)
				return ctx.Err()
			case <-changed:
				stopTimer(timer)
				continue
			case <-timer.C:
				return os.ErrDeadlineExceeded
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (window *sendWindow) setDeadline(deadline time.Time) {
	window.mu.Lock()
	defer window.mu.Unlock()
	window.deadline = deadline
	close(window.changed)
	window.changed = make(chan struct{})
}

func (window *sendWindow) update(streamID, increment uint32) error {
	window.mu.Lock()
	defer window.mu.Unlock()
	switch streamID {
	case 0:
		if increment > InitialConnectionWindow-window.connection {
			return errors.New("artx connection window overflow")
		}
		window.connection += increment
	case 1:
		if increment > InitialStreamWindow-window.stream {
			return errors.New("artx stream window overflow")
		}
		window.stream += increment
	default:
		return errors.New("artx invalid WINDOW_UPDATE stream")
	}
	close(window.changed)
	window.changed = make(chan struct{})
	return nil
}

func knownFrame(frameType byte) bool {
	switch frameType {
	case FrameAuth, FrameSettings, FrameTCPSyn, FrameData, FrameFin, FrameRST, FrameWindowUpdate,
		FrameUDPAssoc, FrameDatagram, FramePadding, FramePing, FramePong:
		return true
	default:
		return false
	}
}

type receiveWindow struct {
	mu         sync.Mutex
	stream     uint32
	connection uint32
}

func newReceiveWindow() *receiveWindow {
	return &receiveWindow{stream: InitialStreamWindow, connection: InitialConnectionWindow}
}

func (window *receiveWindow) consume(amount int) error {
	window.mu.Lock()
	defer window.mu.Unlock()
	if amount < 0 || uint32(amount) > window.stream || uint32(amount) > window.connection {
		return errors.New("artx peer exceeded receive window")
	}
	window.stream -= uint32(amount)
	window.connection -= uint32(amount)
	return nil
}

func (window *receiveWindow) restore(increment uint32) error {
	window.mu.Lock()
	defer window.mu.Unlock()
	if increment > InitialStreamWindow-window.stream || increment > InitialConnectionWindow-window.connection {
		return errors.New("artx receive window overflow")
	}
	window.stream += increment
	window.connection += increment
	return nil
}

type receiveBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	capacity uint32
	closed   bool
	err      error
	changed  chan struct{}
}

func newReceiveBuffer(capacity uint32) *receiveBuffer {
	return &receiveBuffer{capacity: capacity, changed: make(chan struct{})}
}

func (buffer *receiveBuffer) write(payload []byte) error {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.closed {
		return buffer.err
	}
	if uint32(buffer.buffer.Len()+len(payload)) > buffer.capacity {
		return errors.New("artx receive buffer overflow")
	}
	_, _ = buffer.buffer.Write(payload)
	buffer.notify()
	return nil
}

func (buffer *receiveBuffer) read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	for {
		buffer.mu.Lock()
		if buffer.buffer.Len() > 0 {
			read, _ := buffer.buffer.Read(payload)
			buffer.mu.Unlock()
			return read, nil
		}
		if buffer.closed {
			err := buffer.err
			buffer.mu.Unlock()
			return 0, err
		}
		changed := buffer.changed
		buffer.mu.Unlock()
		<-changed
	}
}

func (buffer *receiveBuffer) close(err error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.closed {
		return
	}
	buffer.closed = true
	buffer.err = err
	buffer.notify()
}

func (buffer *receiveBuffer) abort(err error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.buffer.Reset()
	buffer.closed = true
	buffer.err = err
	buffer.notify()
}

func (buffer *receiveBuffer) notify() {
	close(buffer.changed)
	buffer.changed = make(chan struct{})
}

func (connection *Conn) SetDeadline(deadline time.Time) error {
	connection.windows.setDeadline(deadline)
	return connection.Conn.SetDeadline(deadline)
}

func (connection *Conn) SetWriteDeadline(deadline time.Time) error {
	connection.windows.setDeadline(deadline)
	return connection.Conn.SetWriteDeadline(deadline)
}
