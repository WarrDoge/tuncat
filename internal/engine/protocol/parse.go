package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// Errors returned by ParseFrame.
var (
	// ErrShortFrame is returned when the buffer is shorter than the 8-byte
	// CSTP header.
	ErrShortFrame = errors.New("protocol: frame shorter than 8-byte CSTP header")
	// ErrBadMagic is returned when the fixed 4-byte prefix (S T F 0x01) is not
	// present.
	ErrBadMagic = errors.New("protocol: bad CSTP magic prefix")
	// ErrPayloadLength is returned when the declared payload length extends
	// past the end of the received bytes.
	ErrPayloadLength = errors.New("protocol: payload length exceeds frame")
)

// ParseFrame parses one CSTP frame from buf and returns its payload type and
// payload bytes.
//
// buf must be the bytes actually received, not the whole read buffer: the
// length field is validated against len(buf), so passing a longer slice than
// was read lets a peer address bytes left over from an earlier frame in a
// pooled buffer.
//
// The returned payload aliases buf and stays valid only until buf is reused.
// Because the declared length is checked before slicing, ParseFrame cannot
// panic on malformed input.
func ParseFrame(buf []byte) (ptype byte, payload []byte, err error) {
	if len(buf) < len(Header) {
		return 0, nil, ErrShortFrame
	}
	if buf[0] != 0x53 || buf[1] != 0x54 || buf[2] != 0x46 || buf[3] != 0x01 {
		return 0, nil, ErrBadMagic
	}

	dataLen := int(binary.BigEndian.Uint16(buf[4:6]))
	if dataLen > len(buf)-len(Header) {
		return 0, nil, ErrPayloadLength
	}

	return buf[6], buf[len(Header) : len(Header)+dataLen], nil
}

// ReadFrame reads exactly one CSTP frame into buf and returns its payload type
// and payload bytes, which alias buf.
//
// A stream read is not frame-aligned: bufio.Reader.Read returns whatever a TCP
// segment happened to deliver, so a frame can arrive split across reads and two
// frames can arrive in one. ReadFrame consumes the 8-byte header, then exactly
// the declared payload, so a split frame is completed rather than rejected and
// a trailing frame stays buffered for the next call.
//
// ErrPayloadLength is returned when the declared length does not fit in buf,
// which is the only case a caller cannot recover from by reading more.
func ReadFrame(r io.Reader, buf []byte) (ptype byte, payload []byte, err error) {
	if len(buf) < len(Header) {
		return 0, nil, ErrShortFrame
	}
	if _, err = io.ReadFull(r, buf[:len(Header)]); err != nil {
		return 0, nil, err
	}
	if buf[0] != 0x53 || buf[1] != 0x54 || buf[2] != 0x46 || buf[3] != 0x01 {
		return 0, nil, ErrBadMagic
	}

	dataLen := int(binary.BigEndian.Uint16(buf[4:6]))
	if dataLen > len(buf)-len(Header) {
		return 0, nil, ErrPayloadLength
	}
	if _, err = io.ReadFull(r, buf[len(Header):len(Header)+dataLen]); err != nil {
		return 0, nil, err
	}

	return buf[6], buf[len(Header) : len(Header)+dataLen], nil
}
