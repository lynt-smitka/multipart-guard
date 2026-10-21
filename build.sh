#!/bin/bash
# Static linux/amd64 binary without CGO. Go 1.23 is the last release line that supports Linux kernel 2.6.32
# (CentOS 6); Go 1.24+ requires kernel 3.2. Uses a local Go toolchain, or Docker image golang:1.23.
set -eu
cd "$(dirname "$0")"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
LDFLAGS="-s -w -X main.version=$VERSION"
mkdir -p dist
GO=${GO:-go}
if command -v "$GO" >/dev/null; then
    "$GO" version
    "$GO" vet ./...
    "$GO" test ./...
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags "$LDFLAGS" -o dist/multipart-guard .
elif command -v docker >/dev/null; then
    docker run --rm -v "$PWD":/src -w /src -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 -e GOCACHE=/tmp/gocache \
        golang:1.23 sh -c "go vet ./... && go test ./... && go build -trimpath -ldflags '$LDFLAGS' -o dist/multipart-guard ."
else
    echo "neither Go nor Docker found" >&2; exit 1
fi
sha256sum dist/multipart-guard | tee dist/multipart-guard.sha256
