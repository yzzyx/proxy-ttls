package main

import (
	"net"
	"time"
)

type EAPTTLSConn struct {
	conn net.Conn
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
