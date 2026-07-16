package artx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type PacketConn struct {
	net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	remote     net.Addr
	frames     lockedFrameWriter
	windows    *sendWindow
	receive    *receiveWindow
	control    chan controlWrite
	updateMu   sync.Mutex
	update     uint32
	updateWake chan struct{}
	packets    chan []byte
	readErr    chan error
	readDone   chan struct{}
	writeMu    sync.Mutex
	closed     atomic.Bool
	closeOnce  sync.Once
}

func NewPacketConn(connection net.Conn, remote net.Addr) *PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	packetConnection := &PacketConn{
		Conn:       connection,
		ctx:        ctx,
		cancel:     cancel,
		remote:     remote,
		frames:     lockedFrameWriter{writer: connection},
		windows:    newSendWindow(),
		receive:    newReceiveWindow(),
		control:    make(chan controlWrite, 4),
		updateWake: make(chan struct{}, 1),
		packets:    make(chan []byte),
		readErr:    make(chan error, 1),
		readDone:   make(chan struct{}),
	}
	go packetConnection.controlLoop()
	go packetConnection.readLoop()
	return packetConnection
}

func (connection *PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	select {
	case packet := <-connection.packets:
		return copy(payload, packet), connection.remote, nil
	case err := <-connection.readErr:
		connection.readErr <- err
		return 0, nil, err
	}
}

func (connection *PacketConn) WriteTo(payload []byte, remote net.Addr) (int, error) {
	if connection.closed.Load() {
		return 0, net.ErrClosed
	}
	if !samePacketDestination(connection.remote, remote) {
		return 0, errors.New("artx UDP destination does not match the association")
	}
	encoded, err := MarshalDatagram(payload)
	if err != nil {
		return 0, err
	}

	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := connection.windows.waitConsume(connection.ctx, len(encoded)); err != nil {
		return 0, err
	}
	if err := connection.frames.write(FrameDatagram, 1, encoded); err != nil {
		connection.finish(err)
		return 0, err
	}
	return len(payload), nil
}

func (connection *PacketConn) Close() error {
	if !connection.closed.CompareAndSwap(false, true) {
		return nil
	}
	connection.cancel()
	_ = connection.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	connection.writeMu.Lock()
	finErr := connection.frames.write(FrameFin, 1, nil)
	connection.writeMu.Unlock()
	if finErr == nil {
		_ = connection.Conn.SetReadDeadline(time.Now().Add(time.Second))
		timer := time.NewTimer(time.Second)
		select {
		case <-connection.readDone:
			stopTimer(timer)
		case <-timer.C:
			connection.closeOnce.Do(func() { _ = connection.Conn.Close() })
			<-connection.readDone
		}
	}
	var closeErr error
	connection.closeOnce.Do(func() { closeErr = connection.Conn.Close() })
	connection.reportReadError(net.ErrClosed)
	return errors.Join(finErr, closeErr)
}

func (connection *PacketConn) LocalAddr() net.Addr {
	return connection.Conn.LocalAddr()
}

func (connection *PacketConn) SetDeadline(deadline time.Time) error {
	connection.windows.setDeadline(deadline)
	return connection.Conn.SetDeadline(deadline)
}

func (connection *PacketConn) SetReadDeadline(deadline time.Time) error {
	return connection.Conn.SetReadDeadline(deadline)
}

func (connection *PacketConn) SetWriteDeadline(deadline time.Time) error {
	connection.windows.setDeadline(deadline)
	return connection.Conn.SetWriteDeadline(deadline)
}

func (connection *PacketConn) readLoop() {
	defer close(connection.readDone)
	for {
		frame, err := ReadFrame(connection.Conn)
		if err != nil {
			connection.finish(err)
			return
		}
		switch frame.Type {
		case FrameDatagram:
			payload, err := ParseDatagram(frame.Payload)
			if err != nil {
				connection.finish(err)
				return
			}
			if err := connection.receive.consume(len(frame.Payload)); err != nil {
				connection.finish(err)
				return
			}
			packet := append([]byte(nil), payload...)
			if !connection.closed.Load() {
				select {
				case connection.packets <- packet:
				case <-connection.ctx.Done():
					if !connection.closed.Load() {
						return
					}
				}
			}
			if err := connection.replenish(uint32(len(frame.Payload))); err != nil {
				connection.finish(err)
				return
			}
		case FrameFin:
			connection.finish(io.EOF)
			return
		case FrameRST:
			connection.finish(errStreamReset)
			return
		case FrameWindowUpdate:
			if len(frame.Payload) != 4 {
				connection.finish(errors.New("invalid artx WINDOW_UPDATE"))
				return
			}
			increment := binary.BigEndian.Uint32(frame.Payload)
			if increment == 0 {
				connection.finish(errors.New("artx zero WINDOW_UPDATE"))
				return
			}
			if err := connection.windows.update(frame.StreamID, increment); err != nil {
				connection.finish(err)
				return
			}
		case FramePadding, FramePong:
		case FramePing:
			if err := connection.queueControl(controlWrite{frameType: FramePong, payload: frame.Payload}); err != nil {
				connection.finish(err)
				return
			}
		default:
			if knownFrame(frame.Type) {
				connection.finish(errors.New("artx unexpected frame in UDP association"))
				return
			}
		}
	}
}

func (connection *PacketConn) replenish(increment uint32) error {
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

func (connection *PacketConn) queueControl(control controlWrite) error {
	select {
	case connection.control <- control:
		return nil
	case <-connection.ctx.Done():
		return connection.ctx.Err()
	}
}

func (connection *PacketConn) controlLoop() {
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
			if err := connection.frames.writeWindowUpdate(increment); err != nil {
				connection.finish(err)
				return
			}
		case control := <-connection.control:
			if err := connection.frames.write(control.frameType, 0, control.payload); err != nil {
				connection.finish(err)
				return
			}
		}
	}
}

func (connection *PacketConn) finish(err error) {
	connection.closed.Store(true)
	connection.cancel()
	connection.closeOnce.Do(func() { _ = connection.Conn.Close() })
	connection.reportReadError(err)
}

func (connection *PacketConn) reportReadError(err error) {
	select {
	case connection.readErr <- err:
	default:
	}
}

func samePacketDestination(expected, actual net.Addr) bool {
	return expected != nil && actual != nil && expected.Network() == actual.Network() && expected.String() == actual.String()
}
