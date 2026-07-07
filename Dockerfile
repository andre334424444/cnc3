# ================================================================
#  nexus CNC — multi-stage Docker build
#
#  Stage 1: compile Go binary (golang:1.21-alpine)
#  Stage 2: run from scratch/alpine (minimal attack surface)
#
#  Build:  docker build -t nexus-cnc .
#  Run:    docker run -d -p 19443:19443 -p 48101:48101 \
#            -v nexus-data:/data --name nexus nexus-cnc
# ================================================================

# --- build stage ---
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY cnc/go.mod cnc/go.sum* ./
RUN go mod download 2>/dev/null || true
COPY cnc/ ./

# Static binary — no libc dependency, runs on scratch.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o nexus-cnc .

# --- runtime stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin nexus

USER nexus
WORKDIR /data

# CNC + admin on 19443, scan listener on 48101
EXPOSE 19443 48101

COPY --from=builder /build/nexus-cnc /nexus-cnc

# Store data in a volume so it survives container restarts.
VOLUME ["/data"]

ENTRYPOINT ["/nexus-cnc", "-port", "19443"]
