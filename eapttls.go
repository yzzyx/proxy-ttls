package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// communicationDir defines the direction of the communication
type communicationDir int

// Constants used to keep track of communication direction
const (
	ClientToServer communicationDir = iota
	ServerToClient
)

func (d communicationDir) String() string {
	smap := map[communicationDir]string{
		ClientToServer: "client->server",
		ServerToClient: "server->client",
	}

	return smap[d]
}

// IdentInfo is passed between the client->server and server->client connections
// in the Proxy to keep identifiers in sync between writes.
//
// When a packet is read from one connection, an IdentInfo is placed in the other connections
// info-channel, so that the next write it makes uses the same identifiers as we just read
type IdentInfo struct {
	EAPIdentifier uint8
	EAPFlags      uint8
	IFTIdentifier uint32
}

type EAPTTLSConn struct {
	net.Conn

	writeIdentCh <-chan IdentInfo // Channel for identifiers that should be used in Write()
	readIdentCh  chan<- IdentInfo // Channel that we add identifiers to in Read()
	direction    communicationDir
}

// beUint32 converts a uint32 to []byte in big endian order
func beUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// Read reads data from the connection
func (c *EAPTTLSConn) Read(b []byte) (n int, err error) {
	var expectedEapCode uint8

	switch c.direction {
	case ClientToServer:
		expectedEapCode = EAPRequest
	case ServerToClient:
		expectedEapCode = EAPResponse
	}

	packet := make([]byte, 16384)
	nb, err := c.Conn.Read(packet)
	if err != nil {
		return 0, err
	}

	packet = packet[0:nb]

	// First, decode the IF-T header
	ift, err := IFTDecode(packet)
	if err != nil {
		return 0, err
	}

	if !ift.IsValidAuth() {
		return 0, errors.New("bad IFT packet")
	}

	// Inside the IF-T packet, we should first have a Juniper1 value...
	val := binary.BigEndian.Uint32(ift.Data)
	if val != Juniper1 {
		return 0, fmt.Errorf("expected IF-T to contain value 0x%x, but got 0x%x", Juniper1, val)
	}

	// ...followed by a EAP packet
	eap, err := EAPDecode(ift.Data[4:])
	if err != nil {
		return 0, err
	}

	if eap.Code != expectedEapCode {
		return 0, fmt.Errorf("unexpected EAP packet code %d (expected %d)", eap.Type, expectedEapCode)
	}

	if eap.Type != EAPTypeTTLS {
		return 0, fmt.Errorf("unexpected EAP type %d (expected %d)", eap.Type, EAPTypeTTLS)
	}

	if len(b) < len(eap.Data) {
		return 0, io.ErrShortBuffer
	}

	ii := IdentInfo{
		EAPIdentifier: eap.Identifier,
		EAPFlags:      eap.Flags,
		IFTIdentifier: ift.Identifier,
	}
	c.readIdentCh <- ii

	nb = copy(b, eap.Data)
	return nb, nil
}

// Write writes data to the connection
func (c *EAPTTLSConn) Write(b []byte) (n int, err error) {
	var eapCode uint8
	var iftCode uint32

	// If we're acting as a client to the server,
	// we'll use the eapIdent the server last gave us, and set th
	// On the client side
	switch c.direction {
	case ServerToClient:
		eapCode = EAPRequest
		iftCode = IFTClientAuthChallenge
	case ClientToServer:
		eapCode = EAPResponse
		iftCode = IFTClientAuthResponse
	}

	idents := <-c.writeIdentCh
	/*

					   Packet server->client:
					   00000000  00 00 55 97 00 00 00 05  00 00 00 5e 00 00 01 f7  |..U........^....|
					   00000010  00 0a 4c 01 01 02 00 4a  15 20 00 00 01 0b 00 00  |..L....J. ......|
					   00000020  00 0c 09 01 00 02 00 00  01 0a 00 00 00 0c 00 00  |................|
					   00000030  05 83 00 00 01 0d 00 00  00 1c 50 75 6c 73 65 20  |..........Pulse |
					   00000040  43 6f 6e 6e 65 63 74 20  53 65 63 75 72 65 00 00  |Connect Secure..|
					   00000050  0d 6b 80 00 00 10 00 00  05 83 00 00 00 02        |.k............|

						IFT:
							   00 00 55 97 - ift vendor (TGC)
							   00 00 00 05 - ift type   auth response
							   00 00 00 5e - length
							   00 00 00 01 - ..
							   00 0a 4c 01 - Juniper1
						EAP:
						       01 - code EapRequest (1) or EapResponse (2)
					           02 - ident
						       00 4a - datalength + 5
						       15 - eap type - EapTTLS
				               20 - EapTTL flags
										0x80 - EapTTLSLengthIncluded
		                                0x40 - EapTTLSFlagMoreFragments
										0x20 - EapTTLSFlagStart

						DATA:
					   00000000                                 00 00 01 0b 00 00  |..L....J. ......|
					   00000020  00 0c 09 01 00 02 00 00  01 0a 00 00 00 0c 00 00  |................|
					   00000030  05 83 00 00 01 0d 00 00  00 1c 50 75 6c 73 65 20  |..........Pulse |
					   00000040  43 6f 6e 6e 65 63 74 20  53 65 63 75 72 65 00 00  |Connect Secure..|
					   00000050  0d 6b 80 00 00 10 00 00  05 83 00 00 00 02        |.k............|


				    0   1   2   3   4   5   6   7
			      +---+---+---+---+---+---+---+---+
			      | L | M | S | R | R |     V     |
			      +---+---+---+---+---+---+---+---+

			      L = Length included
			      M = More fragments
			      S = Start
			      R = Reserved
			      V = Version (000 for EAP-TTLSv0)

			      The L bit is set to indicate the presence of the four-octet TLS
			      Message Length field.  The M bit indicates that more fragments are
			      to come.  The S bit indicates a Start message.  The V field is set
			      to the version of EAP-TTLS, and is set to 000 for EAP-TTLSv0.






									   	packet := CreateIFTHeader(VendorTGC, IFTTypeAuthResponse)
											buf := make([]byte, 16)
											binary.BigEndian.PutUint32(buf[:], vendor)
											binary.BigEndian.PutUint32(buf[4:], iftType)
											binary.BigEndian.PutUint32(buf[8:], 0)
											binary.BigEndian.PutUint32(buf[12:], 0)
									   	packet = append(packet, beUint32(Juniper1)...)

									   	// Length is length of b + flags
									   	packet = append(packet, CreateEAPHeader(code, c.eapIdent, EAPTypeTTLS, 0, uint16(len(b)+1))...)
											buf[0] = code
											buf[1] = ident

											if eapType == EapTypeExpandedTypes {
												binary.BigEndian.PutUint16(buf[2:], length+12)
												binary.BigEndian.PutUint32(buf[4:], ExpandedJuniper)
												binary.BigEndian.PutUint32(buf[8:], subtype)
												return buf[0:12]
											}

											binary.BigEndian.PutUint16(buf[2:], length+5)
											buf[4] = uint8(eapType)
									   	packet = append(packet, 0x00) // EAP-TTLS flags
									   	packet = append(packet, b...)
	*/

	// First, wrap data in a EAP packet
	eap := NewEAP(eapCode, idents.EAPIdentifier, EAPTypeTTLS, idents.EAPFlags, b)

	// Then wrap the EAP packet in a IFT packet
	ift := NewIFT(VendorTGC, iftCode, idents.IFTIdentifier, append(beUint32(Juniper1), eap.Encode()...))
	nb, err := c.Conn.Write(ift.Encode())
	if err != nil {
		return 0, err
	}

	if nb < int(ift.Length) {
		return 0, io.ErrShortWrite
	}

	return len(b), nil
}
