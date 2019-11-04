package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

var outputWriter io.Writer
var keylogWriter io.Writer
var serverCert tls.Certificate
var clientCert *tls.Certificate

var keylogFilename = flag.String("keylog", "", "write tls keys to file")
var outputFilename = flag.String("output", "", "set output file")
var forwardAddress = flag.String("forward", "", "forward requests to")
var flagUsePKCS11 = flag.Bool("pkcs11", false, "use pkcs11 for client certificate key")
var flagClientCert = flag.String("client-cert", "", "path to client certificate, if used")
var flagClientKey = flag.String("client-key", "", "path to client key, if used")
var flagServerCert = flag.String("server-cert", "cert.pem", "path to server certificate")
var flagServerKey = flag.String("server-key", "key.pem", "path to server key")

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

	serverIdentCh chan IdentInfo
	clientIdentCh chan IdentInfo

	useTTLS bool

	done chan struct{}
}

// Reader forwards all data from client to clientCh, or from server to serverCh
func NewProxy(clientConn, serverConn net.Conn) *Proxy {
	p := &Proxy{
		clientConn:    clientConn,
		serverConn:    serverConn,
		clientCh:      make(chan []byte),
		serverCh:      make(chan []byte),
		done:          make(chan struct{}),
		serverIdentCh: make(chan IdentInfo, 100),
		clientIdentCh: make(chan IdentInfo, 100),
	}

	return p
}

// SetupTTLS wraps an existing connection with a TTLS connection,
// and returns the TTLS connection
func (p *Proxy) SetupTTLSClient(packet []byte) error {
	// Get Identifier info from the Start TTLS-packet
	ift, err := IFTDecode(packet)
	if err != nil {
		return err
	}

	eap, err := EAPDecode(ift.Data[4:])
	if err != nil {
		return err
	}

	ii := IdentInfo{
		EAPIdentifier: eap.Identifier,
	}

	// Create two EAP-TTLS wrappers,
	// one for the server connection and one for the client connection.
	//
	// They both have the readIdent/writeIdent channels switched between them,
	// so identifiers from the server are copied to the client and vice-versa
	serverEAP := &EAPTTLSConn{
		Conn:          p.serverConn,
		direction:     ClientToServer,
		readIdentCh:   p.serverIdentCh,
		writeIdentCh:  p.clientIdentCh,
		IFTIdentifier: ift.Identifier, // Keep increasing the IFT identifiers when communicating with the server
	}

	// Add identifier info to channel, so that it can be used in the handshake process
	p.clientIdentCh <- ii

	fmt.Fprintf(outputWriter, "Setting up client->server EAP-TTLS\n")
	config := &tls.Config{
		InsecureSkipVerify:          true,
		MaxVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	}

	if clientCert != nil {
		config.Certificates = []tls.Certificate{*clientCert}
	}
	c := tls.Client(serverEAP, config)
	err = c.Handshake()
	if err != nil {
		return err
	}
	fmt.Fprintf(outputWriter, "client->server Handshake is done!")
	p.serverConn = c
	return nil
}

func (p *Proxy) SetupTTLSServer(packet []byte) error {
	// Get Identifier info from the Start TTLS-packet
	ift, err := IFTDecode(packet)
	if err != nil {
		return err
	}

	eap, err := EAPDecode(ift.Data[4:])
	if err != nil {
		return err
	}

	ii := IdentInfo{
		EAPIdentifier: eap.Identifier,
	}

	clientEAP := &EAPTTLSConn{
		Conn:         p.clientConn,
		direction:    ServerToClient,
		readIdentCh:  p.clientIdentCh,
		writeIdentCh: p.serverIdentCh,
		hasData:      true,
		data:         eap.Data,
	}

	p.serverIdentCh <- ii

	cfg := &tls.Config{
		Certificates:                []tls.Certificate{serverCert},
		MaxVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
		ClientAuth:                  tls.RequestClientCert,
	}

	fmt.Fprintf(outputWriter, "Setting up server->client EAP-TTLS, with initial packet data set\n")
	c := tls.Server(clientEAP, cfg)
	err = c.Handshake()
	if err != nil {
		return err
	}
	fmt.Fprintf(outputWriter, "server->client handshake done\n")

	p.clientConn = c

	return nil
}

// Reader forwards all data from client to server, or from server to client
func (p *Proxy) Reader(direction communicationDir) error {
	var src net.Conn
	var dest net.Conn
	clientTTLSconfigured := false

	buf := make([]byte, 32*1024)
	for {
		switch direction {
		case ClientToServer:
			src = p.clientConn
			dest = p.serverConn
		case ServerToClient:
			src = p.serverConn
			dest = p.clientConn
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			packet := buf[0:nr]

			ttlsStr := ""
			if p.useTTLS && (direction == ServerToClient || clientTTLSconfigured) {
				ttlsStr = " [EAP-TTLS]"
			}
			fmt.Fprintf(outputWriter, "Packet %s%s:\n%s", direction, ttlsStr, hex.Dump(packet))

			// If we've initiated a TTLS connection on the server side, we need to do the same on the client side,
			// but we're now acting as a server, which means that the first packet we receive will be from the
			// original connection.
			if direction == ClientToServer && p.useTTLS && !clientTTLSconfigured {
				clientTTLSconfigured = true

				err = p.SetupTTLSServer(packet)
				if err != nil {
					return err
				}
				continue
			}

			nw, e := dest.Write(packet)
			if e != nil {
				return e
			}
			if nw < nr {
				return io.ErrShortWrite
			}

			// If the server sent a start TTLS-packet, initiate a new TTLS-communication with the server side
			if direction == ServerToClient && !p.useTTLS && isStartTTLS(buf) {
				p.useTTLS = true
				err = p.SetupTTLSClient(packet)
				if err != nil {
					return err
				}
			}

		}

		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Timeout() {
					src.SetReadDeadline(time.Time{})
					fmt.Println(direction, "is timeout!")
					continue
				}
			}

			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func handleClient(clientConn net.Conn) error {
	defer clientConn.Close()

	config := tls.Config{
		KeyLogWriter:       keylogWriter,
		InsecureSkipVerify: true,
	}

	if clientCert != nil {
		config.Certificates = []tls.Certificate{*clientCert}
	}

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
			fmt.Fprintf(outputWriter, "%s: error from reader: %s (%T %v)\n", ClientToServer, err, err, err)
		}
	}()

	err = p.Reader(ServerToClient)
	if err != nil {
		fmt.Fprintf(outputWriter, "%s: error from reader: %s (%T %v)\n", ServerToClient, err, err, err)
	}
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

	serverCert, err = tls.LoadX509KeyPair(*flagServerCert, *flagServerKey)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	// Use client certificate when communicating upstream?
	if *flagClientCert != "" {
		var cc tls.Certificate
		if !*flagUsePKCS11 {
			cc, err = tls.LoadX509KeyPair(*flagClientCert, *flagClientKey)
			if err != nil {
				log.Fatalf("server: LoadX509KeyPair failed for client certificates: %s", err)
			}
		} else {
			cc, err = LoadCertificate(*flagClientCert)
			if err != nil {
				log.Fatalf("server: LoadCertificate failed for client certificates: %s", err)
			}

			ctx, err := crypto11.ConfigureFromFile("pkcs11.conf")
			if err != nil {
				log.Printf("Cannot configure from file: %s", err)
				return
			}
			defer ctx.Close()

			keyPairs, err := ctx.FindAllKeyPairs()
			if err != nil {
				log.Printf("Cannot find all keyspairs: %s", err)
				return
			}

			for _, kp := range keyPairs {
				cc.PrivateKey = kp
				fmt.Printf("publickey: %T %v\n", kp, kp)
			}
		}
		clientCert = &cc
		config := tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*clientCert},
		}

		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
				TLSClientConfig:    &config,
			},
		}
		resp, err := client.Get("https://test-navet.karolinska.se")
		if err != nil {
			log.Fatalf("client.Get: %s", err)
		}

		fmt.Println("Response", resp.StatusCode, resp.Status)
		fmt.Println("Headers", resp.Header)

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("ioutil.ReadAll: %s", err)
		}
		fmt.Println("Body:\n", b)
		return
	}

	config := tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
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
			log.Printf("server: client %s disconnected", conn.RemoteAddr())
		}()
	}
}
