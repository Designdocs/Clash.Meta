// Package tlsfragment splits a TLS ClientHello across several records so that
// the SNI host name never appears whole in any one of them. It targets the
// cheap plaintext-matching middleboxes found on campus and hotel networks, not
// DPI that reassembles TCP streams.
package tlsfragment

const (
	recordHeaderLen = 5

	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01

	extensionServerName = 0x0000
	nameTypeHostName    = 0x00
)

// Fragment splits one complete ClientHello record into two legal TLS records
// whose boundary falls inside the SNI host name. Handshake messages are allowed
// to span records, so both halves stay protocol-legal.
//
// It reports false whenever buf is not exactly one whole ClientHello record —
// a partial record, several records batched together, or any other content —
// and the caller must then send buf unchanged.
func Fragment(buf []byte) ([][]byte, bool) {
	if len(buf) <= recordHeaderLen {
		return nil, false
	}
	if buf[0] != recordTypeHandshake || buf[1] != 0x03 {
		return nil, false
	}
	if int(buf[3])<<8|int(buf[4]) != len(buf)-recordHeaderLen {
		return nil, false
	}

	payload := buf[recordHeaderLen:]
	if payload[0] != handshakeTypeClientHello {
		return nil, false
	}

	cut, ok := ClientHelloSplitPoint(payload)
	if !ok {
		// A ClientHello we could not walk is not the same as one without a
		// name to hide, so keep splitting rather than silently giving up.
		cut = len(payload) / 2
	}
	if cut <= 0 || cut >= len(payload) {
		return nil, false
	}

	return [][]byte{
		buildRecord(buf[1], buf[2], payload[:cut]),
		buildRecord(buf[1], buf[2], payload[cut:]),
	}, true
}

func buildRecord(major, minor byte, payload []byte) []byte {
	record := make([]byte, 0, recordHeaderLen+len(payload))
	record = append(record, recordTypeHandshake, major, minor,
		byte(len(payload)>>8), byte(len(payload)))
	return append(record, payload...)
}

// ClientHelloSplitPoint returns an offset within payload that lands in the
// middle of the SNI host name. payload is the handshake message, starting with
// its 1-byte type and 3-byte length.
func ClientHelloSplitPoint(payload []byte) (int, bool) {
	offset, length, ok := serverNameOffset(payload)
	if !ok || length < 2 {
		return 0, false
	}
	return offset + length/2, true
}

// serverNameOffset walks the ClientHello to locate the SNI host name. Every
// length prefix comes off the wire, so each one is bounds-checked before use.
func serverNameOffset(payload []byte) (offset, length int, ok bool) {
	if len(payload) < 4 || payload[0] != handshakeTypeClientHello {
		return 0, 0, false
	}
	messageLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if len(body) < messageLen {
		return 0, 0, false
	}
	body = body[:messageLen]

	// Where body starts inside payload, so offsets can be reported against it.
	const bodyBase = 4

	cursor := 0
	// client_version(2) + random(32)
	if len(body) < cursor+34 {
		return 0, 0, false
	}
	cursor += 34

	// session_id
	if len(body) < cursor+1 {
		return 0, 0, false
	}
	size := int(body[cursor])
	cursor++
	if len(body) < cursor+size {
		return 0, 0, false
	}
	cursor += size

	// cipher_suites
	if len(body) < cursor+2 {
		return 0, 0, false
	}
	size = int(body[cursor])<<8 | int(body[cursor+1])
	cursor += 2
	if len(body) < cursor+size {
		return 0, 0, false
	}
	cursor += size

	// compression_methods
	if len(body) < cursor+1 {
		return 0, 0, false
	}
	size = int(body[cursor])
	cursor++
	if len(body) < cursor+size {
		return 0, 0, false
	}
	cursor += size

	// extensions
	if len(body) < cursor+2 {
		return 0, 0, false
	}
	size = int(body[cursor])<<8 | int(body[cursor+1])
	cursor += 2
	end := cursor + size
	if len(body) < end {
		return 0, 0, false
	}

	for cursor+4 <= end {
		extensionType := int(body[cursor])<<8 | int(body[cursor+1])
		extensionLen := int(body[cursor+2])<<8 | int(body[cursor+3])
		cursor += 4
		if cursor+extensionLen > end {
			return 0, 0, false
		}
		if extensionType == extensionServerName {
			return hostNameOffset(body[cursor:cursor+extensionLen], bodyBase+cursor)
		}
		cursor += extensionLen
	}
	return 0, 0, false
}

// hostNameOffset locates the host name inside a server_name extension. base is
// where the extension body sits inside the payload.
func hostNameOffset(extension []byte, base int) (offset, length int, ok bool) {
	if len(extension) < 2 {
		return 0, 0, false
	}
	listLen := int(extension[0])<<8 | int(extension[1])
	if len(extension) < 2+listLen {
		return 0, 0, false
	}
	list := extension[2 : 2+listLen]

	cursor := 0
	for cursor+3 <= len(list) {
		nameType := list[cursor]
		nameLen := int(list[cursor+1])<<8 | int(list[cursor+2])
		cursor += 3
		if cursor+nameLen > len(list) {
			return 0, 0, false
		}
		if nameType == nameTypeHostName {
			return base + 2 + cursor, nameLen, true
		}
		cursor += nameLen
	}
	return 0, 0, false
}
