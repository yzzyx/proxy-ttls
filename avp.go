// from https://raw.githubusercontent.com/zenreach/go-radiuslib/master/avp.go
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// PrintAVP prints a AVP Packet
func PrintAVP(w io.Writer, b []byte) {

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

		fmt.Fprintf(w, "AVP 0x%x ", avpCode)
		if flags&0x80 > 0 {
			vendorId := binary.BigEndian.Uint32(b[8:])
			fmt.Fprintf(w, " vendor 0x%x ", vendorId)
			headerLen += 4
		}
		fmt.Fprintf(w, " (%d bytes):\n", packetLen-headerLen)
		fmt.Fprintf(w, "%s\n", hex.Dump(b[headerLen:packetLen]))
		b = b[packetLen:]
	}
}
