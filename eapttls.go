package main

import (
	"encoding/binary"
	"net"
	"time"
)

const ExpandedJuniper uint32 = (uint32(EapTypeExpandedTypes) << 24) | VendorJuniper

// communicationDir defines the direction of the communication
type communicationDir int

// Constants used to keep track of communication direction
const (
	DirClientToServer communicationDir = iota
	DirServerToClient
)

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

// Read reads data from the connection
func (c *EAPTTLSConn) Read(b []byte) (n int, err error) {
	data := make([]byte, 16384)
	nb, err := c.conn.Read(data)
	if err != nil {
		return nb, err
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

// Write writes data to the connection
func (c *EAPTTLSConn) Write(b []byte) (n int, err error) {

	// On the client side
	code := EAPResponse
	if c.direction == DirServerToClient {
		code = EAPRequest
	}

	packet := CreateIFTHeader(VendorTGC, IFTTypeAuthResponse)
	packet = append(packet, beUint32(Juniper1)...)
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
