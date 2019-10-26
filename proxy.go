package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var outputWriter io.Writer
var keylogWriter io.Writer
var tlsCert tls.Certificate
var keylogFilename = flag.String("keylog", "", "write tls keys to file")
var outputFilename = flag.String("output", "", "set output file")
var forwardAddress = flag.String("forward", "", "forward requests to")

const VendorJuniper = 0xa4c
const VendorTGC = 0x5597
const Juniper1 = (VendorJuniper << 8) | 1

/*
Check if server is trying to initalize a TTLS connection with a Start TTLS packet:

Packet server->client:
00000000  00 00 55 97 00 00 00 05  00 00 00 5e 00 00 01 f7  |..U........^....|
00000010  00 0a 4c 01 01 02 00 4a  15 20 00 00 01 0b 00 00  |..L....J. ......|
00000020  00 0c 09 01 00 02 00 00  01 0a 00 00 00 0c 00 00  |................|
00000030  05 83 00 00 01 0d 00 00  00 1c 50 75 6c 73 65 20  |..........Pulse |
00000040  43 6f 6e 6e 65 63 74 20  53 65 63 75 72 65 00 00  |Connect Secure..|
00000050  0d 6b 80 00 00 10 00 00  05 83 00 00 00 02        |.k............|
*/
func isStartTTLS(buf []byte) bool {

	if len(buf) < 0x18 {
		return false
	}

	ttlsStart := []byte{0x00, 0x00, 0x55, 0x97, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00}
	if buf[0x18] != EAPTypeTTLS {
		return false
	}

	return bytes.Compare(buf[0:len(ttlsStart)], ttlsStart) == 0
}

type Proxy struct {
	clientConn net.Conn
	serverConn net.Conn

	// Channels for data received from client or server
	clientCh chan []byte
	serverCh chan []byte

	done chan struct{}
}

// Reader forwards all data from client to clientCh, or from server to serverCh
func NewProxy(clientConn, serverConn net.Conn) *Proxy {
	p := &Proxy{
		clientConn: clientConn,
		serverConn: serverConn,
		clientCh:   make(chan []byte),
		serverCh:   make(chan []byte),
		done:       make(chan struct{}),
	}

	return p
}

// SetupTTLS wraps an existing connection with a TTLS connection,
// and returns the TTLS connection
func (p *Proxy) SetupTTLS(original net.Conn, dir communicationDir) error {

	serverIdentCh := make(chan IdentInfo)
	clientIdentCh := make(chan IdentInfo)

	// Create two EAP-TTLS wrappers,
	// one for the server connection and one for the client connection.
	//
	// They both have the readIdent/writeIdent channels switched between them,
	// so identifiers from the server are copied to the client and vice-versa
	serverEAP := &EAPTTLSConn{
		Conn:         p.serverConn,
		direction:    ClientToServer,
		readIdentCh:  serverIdentCh,
		writeIdentCh: clientIdentCh,
	}

	clientEAP := &EAPTTLSConn{
		Conn:         p.clientConn,
		direction:    ServerToClient,
		readIdentCh:  clientIdentCh,
		writeIdentCh: serverIdentCh,
	}

	c := tls.Client(serverEAP, &tls.Config{InsecureSkipVerify: true})
	err := c.Handshake()
	if err != nil {
		return err
	}
	p.serverConn = c

	c = tls.Server(clientEAP, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	p.clientConn = c
	return nil
}

// Reader forwards all data from client to clientCh, or from server to serverCh
func (p *Proxy) Reader(direction communicationDir) error {
	var src net.Conn
	var ch chan []byte

	switch direction {
	case ClientToServer:
		src = p.clientConn
		ch = p.clientCh
	case ServerToClient:
		src = p.serverConn
		ch = p.serverCh
	}

	defer close(ch)

	buf := make([]byte, 32*1024)
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			ch <- buf[0:nr]
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// CopyData reads data from the client and server channels and writes them to the correct connection
func (p *Proxy) CopyData() error {
	var err error
	useTTLS := false

	for {
		var buf []byte
		var dst net.Conn
		var direction communicationDir
		var isStartTTLSpacket bool

		select {
		case buf = <-p.clientCh:
			dst = p.serverConn
			direction = ClientToServer
		case buf = <-p.serverCh:
			dst = p.clientConn
			direction = ServerToClient

			if isStartTTLS(buf) {
				// If server sent a  Start-TTLS packet, we'll have to:
				//  * Initiate handshake with the server
				//  * Send the packet to the client, and wait for the client to initiate handshake with us
				useTTLS = true
				isStartTTLSpacket = true

				// Note that we're now replacing our serverConnection with the wrapped version
				p.serverConn, err = p.SetupTTLS(p.serverConn, ClientToServer)
				if err != nil {
					return err
				}

				// We first prepare the client connection for accepting TLS data
				// Note that we must then send the start-packet to the client,
				// but not through the new TTLS connection, which is why 'dst' is not updated
				p.clientConn, err = p.SetupTTLS(p.clientConn, ServerToClient)
				if err != nil {
					return err
				}
			}
		case <-p.done:
			return nil
		}

		if useTTLS && !isStartTTLSpacket {
			fmt.Fprintf(outputWriter, "Packet %s:\n", direction)
			PrintAVP(outputWriter, buf)
		} else {
			_, _ = fmt.Fprintf(outputWriter, "Packet %s:\n%s", direction, hex.Dump(buf))
		}

		nb, err := dst.Write(buf)
		if err != nil {
			return err
		}

		if nb != len(buf) {
			return io.ErrShortWrite
		}
	}
}

func handleClient(clientConn net.Conn) error {
	defer clientConn.Close()

	config := tls.Config{KeyLogWriter: keylogWriter, InsecureSkipVerify: true}
	serverConn, err := tls.Dial("tcp", *forwardAddress, &config)
	if err != nil {
		err = fmt.Errorf("error initializing TLS connection: %w", err)
		return err
	}
	defer serverConn.Close()

	p := NewProxy(clientConn, serverConn)
	go func() {
		err = p.Reader(ClientToServer)
		if err != nil {
			fmt.Fprintf(outputWriter, "%s: error from reader: %s\n", ClientToServer, err)
		}
	}()

	go func() {
		err = p.Reader(ServerToClient)
		if err != nil {
			fmt.Fprintf(outputWriter, "%s: error from reader: %s\n", ServerToClient, err)
		}
	}()

	err = p.CopyData()
	return err
}

func main() {
	var err error
	flag.Parse()

	if *forwardAddress == "" {
		fmt.Println("Forward address must be specified")
		flag.Usage()
		return
	}

	if !strings.Contains(*forwardAddress, ":") {
		newAddr := *forwardAddress + ":443"
		forwardAddress = &newAddr
	}

	outputWriter = os.Stdout
	if *outputFilename != "" {
		f, err := os.Create(*outputFilename)
		if err != nil {
			log.Fatalf("cannot open file: %s", err)
		}
		outputWriter = io.MultiWriter(os.Stdout, f)
		fmt.Println("Logging to", *outputFilename)
	}

	if *keylogFilename != "" {
		keylogWriter, err = os.OpenFile(*keylogFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Println("Cannot open keylog file:", err)
			return
		}
		fmt.Fprintf(keylogWriter, "# SSL/TLS secrets log file, generated by go\n")
		fmt.Println("Writing TLS keys to", *keylogFilename)
	}

	tlsCert, err = tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{tlsCert}}
	service := "0.0.0.0:443"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Printf("server: listening on %s for https, connects to https://%s", service, *forwardAddress)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go func() {
			err = handleClient(conn)
			if err != nil {
				fmt.Fprintf(outputWriter, "error from handleClient: %s\n", err)
			}
		}()
	}
}
