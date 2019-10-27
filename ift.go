package main

import (
	"encoding/binary"
	"errors"
)

// IFT errors
var (
	ErrIFTTooShort       = errors.New("invalid IFT packet - too short")
	ErrIFTLengthMismatch = errors.New("invalid IFT packet - length does not match received data")
)

// IFT Types
const (
	IFTClientAuthRequest   = 3
	IFTClientAuthSelection = 4
	IFTClientAuthChallenge = 5
	IFTClientAuthResponse  = 6
	IFTClientAuthSuccess   = 7
)

// IFTPacket describes a IF-T packet structure according to the
// specification from TNC::
// https://trustedcomputinggroup.org/wp-content/uploads/TNC_IFT_TLS_v2_0_r8.pdf
//
// Basic packet layout:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Reserved   |           Message Type Vendor ID              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Message Type                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Message Length                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Message Identifier                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Message Value (e.g. IF-TNCCS Message) . . . .       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reserved
// This field MUST be set to 0 upon transmission and MUST be ignored by compliant IF-T message recipient implementations.
//
// Message Type Vendor ID
// This field indicates the owner of the name space associated with the Message Type.
// This is accomplished by specifying the 24 bit SMI Private Enterprise Number Vendor ID of the party who owns the
// Message Type name space. TCG unique (not in IETF NEA’s specification) standard messages defined in this specification
// MUST use the TCG SMI Private Enterprise Number value (0x005597) in this field. Values shared with the IETF MUST use
// the IETF SMI Private Enterprise Number value (0) in this field.
//
// Message Type
// This field defines the type of the IF-T message (within the scope of the specified vendor name space included in the
// Message ValueVendor ID field).  Recipients of a message containing a vendor id and message type that is unrecognized
// SHOULD respond with an IETF NEA Type Not Supported error code in an IF-T Binding to TLS Error message.NAA and NAR
// MUST NOT require support for particular vendor-defined IF-T Message Types and MUST interoperate with other parties
// despite any differences in the set of vendor-defined IF-T Message Types supported (although they MAY permit
// administrators to configure them to require support for specific vendor-defined IF-T message types).The Message Type
// value of 0xffffffff is reserved.  NAA and NAR MUST NOT send IF-T messages in which the IF-T Message Type has this
// reserved value (0xffffffff).  If an NAA or NAR receives a message in which the Message Type has this reserved value
// (0xffffffff), it SHOULD respond with an IETF NEA Invalid Parameter error code in an IF-T Binding to TLS Error message.
//
// Message Length
// This field contains the length in octets of the entire IF-T message (including the entire header).
// Therefore, this value MUST always be at least 16. Any NAA and NAR that receives a message with a Message Length field
// whose value is less than 16 SHOULD respond with an IETF NEA Invalid Parameter in an IF-T Error message.
// Similarly, if a NAA or NAR receives an IF-T message for a Message Type that has a known Message Length and the
// Message Length indicates a different value (greater or less than the expected value), the recipient SHOULD respond
// with an IETF NEA Invalid Parameter error code in an IF-T Binding to TLS Error message.
//
// Message Identifier
// This field contains a value that uniquely identifies the IF-T message on a per message sender (NAR or NAA) basis.
// This value can be copied into the body of a response message to indicate which message was received and caused the
// response. For example, this field is included in the IF-T Error Message so the recipient can determine which message
// sent caused the error. The Message Identifier MUST be a monotonically increasing counter starting at zero indicating
// the number of the messages the sender has transmitted over the TLS session.  It is possible that a busy or long lived
// session might exceed 2^32-1 messages sent, so the message sender MUST roll over to zero upon reaching the 2^32nd
// message, thus restarting the increasing counter. During a rollover, it is feasible that the message recipient could
// be confused if it keeps track of every previously received Message Identifier, so recipients MUST be able to handle
// roll over situations without generating errors.
//
// Message Value
// The contents of this field vary depending on the particular Message Type being expressed.
// This field normally contains an IF-TNCCS message.
type IFTPacket struct {
	Vendor     uint32
	Type       uint32
	Length     uint32
	Identifier uint32
	Data       []byte
}

func (p *IFTPacket) Encode() []byte {
	// Calculate length based on Data
	p.Length = uint32(len(p.Data) + 16)

	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[:], p.Vendor)
	binary.BigEndian.PutUint32(buf[4:], p.Type)
	binary.BigEndian.PutUint32(buf[8:], p.Length)
	binary.BigEndian.PutUint32(buf[12:], p.Identifier)

	return append(buf, p.Data...)
}

func (p *IFTPacket) IsValidAuth() bool {
	if p.Length < 0x14 ||
		p.Vendor != VendorTGC ||
		(p.Type != IFTClientAuthChallenge && p.Type != IFTClientAuthResponse) ||
		binary.BigEndian.Uint32(p.Data) != Juniper1 {
		return false
	}
	return true
}

func IFTDecode(b []byte) (*IFTPacket, error) {
	if len(b) < 16 {
		return nil, ErrIFTTooShort
	}

	p := &IFTPacket{}
	p.Vendor = binary.BigEndian.Uint32(b[:])
	p.Type = binary.BigEndian.Uint32(b[4:])
	p.Length = binary.BigEndian.Uint32(b[8:])
	p.Identifier = binary.BigEndian.Uint32(b[12:])

	if int(p.Length) != len(b) {
		return nil, ErrIFTLengthMismatch

	}

	p.Data = b[16:]
	return p, nil
}

func NewIFT(vendor, iftType, identifier uint32, data []byte) *IFTPacket {
	return &IFTPacket{
		Vendor:     vendor,
		Type:       iftType,
		Identifier: identifier,
		Data:       data,
	}
}
