package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

const ExpandedJuniper uint32 = (uint32(EapTypeExpandedTypes) << 24) | VendorJuniper

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

const IFTClientAuthRequest = 3
const IFTClientAuthSelection = 4
const IFTClientAuthChallenge = 5
const IFTClientAuthResponse = 6
const IFTClientAuthSuccess = 7

type EAPTTLSConn struct {
	conn     net.Conn
	eapIdent uint8

	direction communicationDir
}

// beUint32 converts a uint32 to []byte in big endian order
func beUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

func CreateIFTHeader(vendor uint32, iftType uint32) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[:], vendor)
	binary.BigEndian.PutUint32(buf[4:], iftType)
	binary.BigEndian.PutUint32(buf[8:], 0)
	binary.BigEndian.PutUint32(buf[12:], 0)
	return buf
}

// CreateEAPHeader creates a new EAP header.
// NOTE: length is the length of the DATA that comes _after_ the EAP header.
// The size of the EAP header will automatically be added the the length.
func CreateEAPHeader(code uint8, ident uint8, eapType EapType, subtype uint32, length uint16) []byte {
	buf := make([]byte, 12)

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
	return buf[0:5]
}

func validIFTAuth(packet []byte) bool {

	if len(packet) < 0x14 ||
		binary.BigEndian.Uint32(packet)&0xffffff != VendorTGC ||
		binary.BigEndian.Uint32(packet[4:]) != IFTClientAuthChallenge ||
		//binary.BigEndian.Uint32(packet[8:]) != l ||
		binary.BigEndian.Uint32(packet[16:]) != Juniper1 {
		return false
	}
	return true

}

func validIFTAuthEAP(packet []byte) bool {
	/* Needs to be a valid IF-T/TLS auth challenge with the
	 * expect Auth Type, *and* the payload has to be a valid
	 * EAP request with correct length field. */
	if !validIFTAuth(packet) ||
		len(packet) < 0x19 ||
		packet[0x14] != EAPRequest ||
		int(binary.BigEndian.Uint16(packet[0x16:])) != len(packet)-0x14 {
		return false
	}

	return true
}

// Read reads data from the connection
func (c *EAPTTLSConn) Read(b []byte) (n int, err error) {
	packet := make([]byte, 16384)
	nb, err := c.conn.Read(packet)
	if err != nil {
		return 0, err
	}

	packet = packet[0:nb]

	if !validIFTAuthEAP(packet) ||
		len(packet) < 0x1a ||
		packet[0x18] != EAPTypeTTLS {
		return 0, errors.New("bad eap packet")
	}

	//vpninfo->ttls_recvlen = vpninfo->ssl_read(vpninfo, (void *)vpninfo->ttls_recvbuf,
	//	16384);
	/*
		vpninfo->ttls_recvlen = vpninfo->ssl_read(vpninfo, (void *)vpninfo->ttls_recvbuf,
			16384);
		if (vpninfo->ttls_recvlen > 0 && vpninfo->dump_http_traffic) {
			vpn_progress(vpninfo, PRG_TRACE,
				_("Read %d bytes of IF-T/TLS EAP-TTLS record\n"),
				vpninfo->ttls_recvlen);
			dump_buf_hex(vpninfo, PRG_TRACE, '<',
				(void *)vpninfo->ttls_recvbuf,
				vpninfo->ttls_recvlen);
		}
		if (!valid_ift_auth_eap(vpninfo->ttls_recvbuf, vpninfo->ttls_recvlen) ||
			vpninfo->ttls_recvlen < 0x1a ||
			vpninfo->ttls_recvbuf[0x18] != EAP_TYPE_TTLS) {
		bad_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				_("Bad EAP-TTLS packet\n"));
			return -EIO;
		}
		vpninfo->ttls_eap_ident = vpninfo->ttls_recvbuf[0x15];
		flags = vpninfo->ttls_recvbuf[0x19];
		if (flags & 0x7f)
		goto bad_pkt;
		if (flags & 0x80) {
			// Length bit.
			if (vpninfo->ttls_recvlen < 0x1e ||
				load_be32(vpninfo->ttls_recvbuf + 0x1a) != vpninfo->ttls_recvlen - 0x1e)
			goto bad_pkt;
			vpninfo->ttls_recvpos = 0x1e;
			vpninfo->ttls_recvlen -= 0x1e;
		} else {
			vpninfo->ttls_recvpos = 0x1a;
			vpninfo->ttls_recvlen -= 0x1a;
		}

	*/
	return 0, nil
}

func PrintAVP(b []byte) {

	//0                   1                   2                   3
	//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|                           AVP Code                            |
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|V M r r r r r r|                  AVP Length                   |
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|                        Vendor-ID (opt)                        |
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|    Data ...
	//+-+-+-+-+-+-+-+-+
	//
	//AVP Code
	//The AVP Code is four octets and, combined with the Vendor-ID field
	//if present, identifies the attribute uniquely.  The first 256 AVP
	//numbers represent attributes defined in RADIUS [RFC2865].  AVP
	//numbers 256 and above are defined in Diameter [RFC3588].
	//
	//	AVP Flags
	//
	//The AVP Flags field is one octet and provides the receiver with
	//information necessary to interpret the AVP.
	//
	//	The 'V' (Vendor-Specific) bit indicates whether the optional
	//Vendor-ID field is present.  When set to 1, the Vendor-ID field is
	//present and the AVP Code is interpreted according to the namespace
	//defined by the vendor indicated in the Vendor-ID field.
	//
	//	The 'M' (Mandatory) bit indicates whether support of the AVP is
	//required.  If this bit is set to 0, this indicates that the AVP
	//may be safely ignored if the receiving party does not understand
	//or support it.  If set to 1, this indicates that the receiving
	//party MUST fail the negotiation if it does not understand the AVP;
	//for a TTLS server, this would imply returning EAP-Failure, for a
	//client, this would imply abandoning the negotiation.
	//
	//	The 'r' (reserved) bits are unused and MUST be set to 0 by the
	//sender and MUST be ignored by the receiver.
	//
	//	AVP Length
	//
	//The AVP Length field is three octets and indicates the length of
	//this AVP including the AVP Code, AVP Length, AVP Flags, Vendor-ID
	//(if present), and Data.
	//
	//AVP Codes can be found in:
	//	https://tools.ietf.org/html/rfc2865#section-5.44  and
	//	https://tools.ietf.org/html/rfc3588#section-4.5
	//
	//The start packet may contain one or more AVP's, for example:
	//
	//00000000                                 00 00 01 0b 00 00  |..L....J. ......|
	//00000020  00 0c 09 01 00 02 00 00  01 0a 00 00 00 0c 00 00  |................|
	//00000030  05 83 00 00 01 0d 00 00  00 1c 50 75 6c 73 65 20  |..........Pulse |
	//00000040  43 6f 6e 6e 65 63 74 20  53 65 63 75 72 65 00 00  |Connect Secure..|
	//00000050  0d 6b 80 00 00 10 00 00  05 83 00 00 00 02        |.k............|
	//
	//00 00 01 0b - AVP Code 0x10b - firmware revision
	//00 - flags
	//00 00 0c - Length 0x0c (code + flag + length + vendorid + datalen) = (8+0) => datalen = 4
	//09 01 00 02 - data
	//
	//00 00 01 0a - AVP Code 0x10a - Vendor ID
	//00 - flags
	//00 00 0c - length 0x0c -> datalen = 4
	//00 00 05 83 - Vendor 0x0583
	//
	//00 00 01 0d - AVP Code 0x10d - Product Name
	//00 - flags
	//00 00 1c - length 0x1c -> datalen = 0x1c - 8 = 20
	//bytesx20 - "Pulse Connect Secure"
	//
	//00 00 0d 6b
	//80 - flags - vendor bit set
	//00 00 10 - length 0x10 => (code + flag + length + vendorid + datalen) = (4+1+3+4+datalen) => datalen = 4
	//00 00 05 83 - vendorid
	//00 00 00 02 - data

	// Loop through all AVP packets and dump them
	for len(b) > 0 {
		avpCode := binary.BigEndian.Uint32(b)
		flags := b[4]
		packetLen := binary.BigEndian.Uint32(b[4:]) & 0xffffff
		headerLen := uint32(8)

		fmt.Printf("AVP 0x%x ", avpCode)
		if flags&0x80 > 0 {
			vendorId := binary.BigEndian.Uint32(b[8:])
			fmt.Printf(" vendor 0x%x ", vendorId)
			headerLen += 4
		}
		fmt.Printf(" (%d bytes):\n", packetLen-headerLen)
		fmt.Printf("%s\n", hex.Dump(b[headerLen:packetLen]))
		b = b[packetLen:]
	}
}

// Write writes data to the connection
func (c *EAPTTLSConn) Write(b []byte) (n int, err error) {

	// On the client side
	code := EAPResponse
	if c.direction == ServerToClient {
		code = EAPRequest
	}
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

	packet := CreateIFTHeader(VendorTGC, IFTClientAuthResponse)
	packet = append(packet, beUint32(Juniper1)...)

	// Length is length of b + flags
	packet = append(packet, CreateEAPHeader(code, c.eapIdent, EAPTypeTTLS, 0, uint16(len(b)+1))...)
	packet = append(packet, 0x00) // EAP-TTLS flags
	packet = append(packet, b...)
	/*
		buf_append_ift_hdr(buf, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE);
		buf_append_be32(buf, JUNIPER_1); // IF-T/TLS Auth Type
		buf_append_eap_hdr(buf, EAP_RESPONSE, vpninfo->ttls_eap_ident,
			EAP_TYPE_TTLS, 0);
		// Flags byte for EAP-TTLS
		buf_append_bytes(buf, "\0", 1);
		buf_append_bytes(buf, data, len);
	*/

	return 0, nil
}

// Close closes the connection.
func (c *EAPTTLSConn) Close() error {
	return nil
}

// LocalAddr returns the local network address.
// ignored
func (c *EAPTTLSConn) LocalAddr() net.Addr {
	return nil

}

// RemoteAddr returns the remote network address.
// ignored
func (c *EAPTTLSConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
// ignored
func (c *EAPTTLSConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// ignored
func (c *EAPTTLSConn) SetReadDeadline(t time.Time) error {
	// ignored
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// ignored
func (c *EAPTTLSConn) SetWriteDeadline(t time.Time) error {
	return nil
}
