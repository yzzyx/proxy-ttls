package main

import (
	"encoding/binary"
	"errors"
)

// EAP errors
var (
	ErrEAPTooShort       = errors.New("invalid EAP packet - too short")
	ErrEAPLengthMismatch = errors.New("invalid EAP packet - length header value does not match received data")
)

// EAP codes
const (
	EAPRequest  uint8 = 1
	EAPResponse uint8 = 2
)

// EAP types
const (
	EAPTypeTTLS = 0x15
)

// EAPPacket describes a EAP-TTLS packet as seen in RFC-5281:
//
// The EAP-TTLS packet format is shown below.  The fields are
// transmitted left to right.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Code      |   Identifier  |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Flags     |        Message Length
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//          Message Length         |             Data...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Code
// 1 for request, 2 for response.
//
// Identifier
// The Identifier field is one octet and aids in matching responses
// with requests.  The Identifier field MUST be changed for each
// request packet and MUST be echoed in each response packet.
//
// Length
// The Length field is two octets and indicates the number of octets
// in the entire EAP packet, from the Code field through the Data
// field.
//
// Type
//
//
//
// Flags
// 0   1   2   3   4   5   6   7
// +---+---+---+---+---+---+---+---+
// | L | M | S | R | R |     V     |
// +---+---+---+---+---+---+---+---+
//
// L = Length included
// M = More fragments
// S = Start
// R = Reserved
// V = Version (000 for EAP-TTLSv0)
//
// The L bit is set to indicate the presence of the four-octet TLS
// Message Length field.  The M bit indicates that more fragments are
// to come.  The S bit indicates a Start message.  The V field is set
// to the version of EAP-TTLS, and is set to 000 for EAP-TTLSv0.
//
// Message Length
// The Message Length field is four octets, and is present only if
// the L bit is set.  This field provides the total length of the raw
// data message sequence prior to fragmentation.
//
// Data
// For all packets other than a Start packet, the Data field consists
// of the raw TLS message sequence or fragment thereof.  For a Start
// packet, the Data field may optionally contain an AVP sequence.
type EAPPacket struct {
	Code          uint8 // 1 for request, 2 for response
	Identifier    uint8
	Length        uint16 // Length is the length of Data + EAP Header
	Type          uint8
	Flags         uint8
	MessageLength uint32
	Data          []byte
}

// Encode creates a byte-array from a given EAP packet
func (p *EAPPacket) Encode() []byte {
	buf := make([]byte, 12)

	buf[0] = p.Code
	buf[1] = p.Identifier
	buf[4] = p.Type
	buf[5] = p.Flags
	p.Length = uint16(len(p.Data) + 6)

	// Is total message length included?
	if p.Flags&0x80 > 0 {
		p.Length += 4
		binary.BigEndian.PutUint16(buf[2:], p.Length)
		binary.BigEndian.PutUint32(buf[6:], p.MessageLength)
		return append(buf[0:10], p.Data...)
	}

	binary.BigEndian.PutUint16(buf[2:], p.Length)
	return append(buf[0:5], p.Data...)
}

// EAPDecode decodes a byte array into a EAP Packet
func EAPDecode(buf []byte) (*EAPPacket, error) {
	if len(buf) < 6 {
		return nil, ErrEAPTooShort
	}

	p := &EAPPacket{}
	p.Code = buf[0]
	p.Identifier = buf[1]
	p.Length = binary.BigEndian.Uint16(buf[2:])
	p.Type = buf[4]
	p.Flags = buf[5]

	if p.Flags&0x80 > 0 {
		p.MessageLength = binary.BigEndian.Uint32(buf[6:])
		p.Data = buf[10:]
	} else {
		p.Data = buf[6:]
	}

	if int(p.Length) != len(buf) {
		return nil, ErrEAPLengthMismatch
	}

	return p, nil
}

func NewEAP(code, identifier, eapType, flags uint8, data []byte) *EAPPacket {
	return &EAPPacket{
		Code:       code,
		Identifier: identifier,
		Type:       eapType,
		Flags:      flags,
		Data:       data,
	}
}
