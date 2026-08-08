//go:build !artxr0 || !linux

package artx

import "net"

func newR0Hook(net.Conn) r0Hook {
	return nil
}
