package main

import (
	"bytes"
	"crypto/rand"
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
var keylogFilename = flag.String("keylog", "", "write tls keys to file")
var outputFilename = flag.String("output", "", "set output file")
var forwardAddress = flag.String("forward", "", "forward requests to")

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

const VendorJuniper = 0xa4c
const VendorTGC = 0x5597
const Juniper1 = ((VendorJuniper << 8) | 1)

const IFTTypeAuthResponse = 6

const EAPRequest = 1
const EAPResponse = 2
const EAPTypeTTLS = 0x15

func isTTLS(buf []byte) bool {

	ttlsStart := []byte{0x00, 0x00, 0x55, 0x97, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00}
	if len(buf) < len(ttlsStart) {
		return false
	}

	return bytes.Compare(buf[0:len(ttlsStart)], ttlsStart) == 0
}

/* slower, by we can print/log everything */
func myrawcopy(dst, src net.Conn, direction string) (written int64, err error) {
	buf := make([]byte, 32*1024)
	realcert := []byte("bdc6804f38fe5ea721f46c2ad24c137c")
	mycert := []byte("4cfb34cdb3813186e7d76c4a51a90941")
	//      realcert := []byte("Upgrade: IF-T/TLS 1.0")
	//      mycert := []byte("xxgrade: xx-T/TLS 1.0")
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			buf := bytes.Replace(buf, realcert, mycert, 1)
			fmt.Fprintf(outputWriter, "Packet %s:\n%s", direction, hex.Dump(buf[0:nr]))
			if isTTLS(buf[:]) {

			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

func myiocopy(dst net.Conn, src net.Conn, direction string) {
	myrawcopy(dst, src, direction)
	//io.Copy(dst,src);
	dst.Close()
	src.Close()
}

func handleclient(c net.Conn) {
	config := tls.Config{KeyLogWriter: keylogWriter, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", *forwardAddress, &config)
	checkError(err)

	go myiocopy(conn, c, "client->server")

	myrawcopy(c, conn, "server->client")
	c.Close()
	conn.Close()
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

	cert, err := tls.LoadX509KeyPair("/home/elias/cert.pem", "/home/elias/key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
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
		go handleclient(conn)
	}
}
