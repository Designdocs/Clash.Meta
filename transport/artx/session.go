package artx

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

var (
	ErrSessionBusy   = errors.New("artx session is busy")
	ErrSessionClosed = errors.New("artx session is closed")
)

type ClientSession struct {
	connection net.Conn
	writeMu    sync.Mutex
	mu         sync.Mutex
	active     *sessionStream
	nextID     uint32
	uses       uint32
	limit      uint32
	closeIdle  bool
	closed     bool
	closeOnce  sync.Once
}

type sessionStream struct {
	id                  uint32
	bridge              net.Conn
	localDone, peerDone bool
	bridgeDone          bool
	direct              bool
	frames              chan Frame
	done                chan struct{}
	doneOnce            sync.Once
}

type sessionPipeConn struct {
	net.Conn
	done      <-chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (connection *sessionPipeConn) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		<-connection.done
	})
	return connection.closeErr
}

func NewClientSession(ctx context.Context, raw net.Conn, config ClientConfig) (*ClientSession, error) {
	config.WireVersion = 2
	connection, err := establishSession(ctx, raw, config, nil, false)
	if err != nil {
		return nil, err
	}
	var sample [1]byte
	if _, err := rand.Read(sample[:]); err != nil {
		_ = connection.Close()
		return nil, err
	}
	session := &ClientSession{connection: connection, nextID: 1, limit: 8 + uint32(sample[0]%9)}
	go session.readLoop()
	return session, nil
}

func (session *ClientSession) OpenTCP(destination Destination) (net.Conn, error) {
	connection, stream, err := session.open(FrameTCPSyn, destination, true)
	if err != nil {
		return nil, err
	}
	return newConn(connection, stream.readFrame, func(frameType byte, streamID uint32, payload []byte) error {
		return session.writeDirect(stream, frameType, streamID, payload)
	}), nil
}

func (session *ClientSession) OpenPacket(destination Destination, remote net.Addr) (*PacketConn, error) {
	if remote == nil {
		return nil, errors.New("artx UDP remote address is required")
	}
	connection, _, err := session.open(FrameUDPAssoc, destination, false)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(connection, remote), nil
}

func (session *ClientSession) open(frameType byte, destination Destination, direct bool) (net.Conn, *sessionStream, error) {
	if err := destination.Validate(); err != nil {
		return nil, nil, err
	}
	session.mu.Lock()
	if session.closed || session.uses >= session.limit || session.nextID == 0 {
		session.mu.Unlock()
		return nil, nil, ErrSessionClosed
	}
	if session.active != nil {
		session.mu.Unlock()
		return nil, nil, ErrSessionBusy
	}
	application, bridge := net.Pipe()
	stream := &sessionStream{id: session.nextID, bridge: bridge, direct: direct, done: make(chan struct{})}
	if direct {
		stream.frames = make(chan Frame, 4)
	}
	session.active = stream
	session.uses++
	if session.nextID > ^uint32(0)-2 {
		session.nextID = 0
	} else {
		session.nextID += 2
	}
	session.mu.Unlock()

	if err := session.write(frameType, stream.id, destination.MarshalBinary()); err != nil {
		_ = application.Close()
		session.close()
		return nil, nil, err
	}
	if direct {
		go session.watchDirectClose(stream)
	} else {
		go session.forward(stream)
	}
	return &sessionPipeConn{Conn: application, done: stream.done}, stream, nil
}

func (stream *sessionStream) readFrame() (Frame, error) {
	select {
	case frame := <-stream.frames:
		return frame, nil
	case <-stream.done:
		return Frame{}, net.ErrClosed
	}
}

func (session *ClientSession) writeDirect(stream *sessionStream, frameType byte, streamID uint32, payload []byte) error {
	if streamID != 0 {
		streamID = stream.id
	}
	if err := session.write(frameType, streamID, payload); err != nil {
		session.close()
		return err
	}
	if frameType == FrameFin || frameType == FrameRST {
		session.mu.Lock()
		if session.active == stream {
			stream.localDone = true
		}
		session.mu.Unlock()
		session.release(stream)
	}
	return nil
}

func (session *ClientSession) watchDirectClose(stream *sessionStream) {
	var payload [1]byte
	_, err := stream.bridge.Read(payload[:])
	session.mu.Lock()
	active := session.active == stream
	if active {
		stream.bridgeDone = true
	}
	session.mu.Unlock()
	if !active {
		return
	}
	if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)) && session.release(stream) {
		return
	}
	session.close()
}

func (session *ClientSession) forward(stream *sessionStream) {
	for {
		frame, err := ReadFrame(stream.bridge)
		if err != nil {
			session.mu.Lock()
			active := session.active == stream
			if active {
				stream.bridgeDone = true
			}
			session.mu.Unlock()
			if !active {
				return
			}
			if (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)) && session.release(stream) {
				return
			}
			session.close()
			return
		}
		streamID := frame.StreamID
		if streamID != 0 {
			streamID = stream.id
		}
		if err := session.write(frame.Type, streamID, frame.Payload); err != nil {
			session.close()
			return
		}
		if frame.Type == FrameFin || frame.Type == FrameRST {
			session.mu.Lock()
			if session.active == stream {
				stream.localDone = true
			}
			session.mu.Unlock()
			session.release(stream)
		}
	}
}

func (session *ClientSession) readLoop() {
	for {
		frame, err := readFrame(session.connection, 2)
		if err != nil {
			session.close()
			return
		}
		if frame.StreamID == 0 && (frame.Type == FramePadding || frame.Type == FramePong) {
			continue
		}
		if frame.StreamID == 0 && frame.Type == FramePing {
			if err := session.write(FramePong, 0, frame.Payload); err != nil {
				session.close()
				return
			}
			continue
		}

		session.mu.Lock()
		stream := session.active
		if stream == nil || frame.StreamID != 0 && frame.StreamID != stream.id {
			session.mu.Unlock()
			session.close()
			return
		}
		bridge := stream.bridge
		direct := stream.direct
		session.mu.Unlock()
		if frame.StreamID != 0 {
			frame.StreamID = 1
		}
		if direct {
			select {
			case stream.frames <- frame:
			case <-stream.done:
				return
			}
		} else {
			if err := WriteFrame(bridge, frame.Type, frame.StreamID, frame.Payload); err != nil {
				session.close()
				return
			}
		}
		if frame.Type == FrameFin || frame.Type == FrameRST {
			session.mu.Lock()
			if session.active == stream {
				stream.peerDone = true
			}
			session.mu.Unlock()
			session.release(stream)
		}
	}
}

func (session *ClientSession) release(stream *sessionStream) bool {
	session.mu.Lock()
	if session.active != stream || !stream.localDone || !stream.peerDone || !stream.bridgeDone {
		session.mu.Unlock()
		return false
	}
	session.active = nil
	stream.doneOnce.Do(func() { close(stream.done) })
	closeSession := session.closeIdle || session.uses >= session.limit || session.nextID == 0
	session.mu.Unlock()
	if closeSession {
		session.close()
	}
	return true
}

func (session *ClientSession) write(frameType byte, streamID uint32, payload []byte) error {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	return writeFrame(session.connection, 2, frameType, streamID, payload)
}

func (session *ClientSession) CloseWhenIdle() {
	session.mu.Lock()
	session.closeIdle = true
	idle := session.active == nil
	session.mu.Unlock()
	if idle {
		session.close()
	}
}

func (session *ClientSession) Close() error {
	session.close()
	return nil
}

func (session *ClientSession) IsClosed() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.closed
}

func (session *ClientSession) close() {
	session.closeOnce.Do(func() {
		session.mu.Lock()
		session.closed = true
		active := session.active
		if active != nil {
			active.doneOnce.Do(func() { close(active.done) })
		}
		session.mu.Unlock()
		if active != nil {
			_ = active.bridge.Close()
		}
		_ = session.connection.Close()
	})
}
