#!/bin/bash
# Load test: ab and wrk against the local environment (tests/env.sh start sanitize). Compares direct (token) and guard.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); RUN=$HERE/run; cd "$RUN" || exit 1
TOKEN=${GUARD_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef}
URL=https://127.0.0.1:8443/dump.php
N=${N:-3000}; C=${C:-20}
mkdir -p data
B=----benchboundary
printf -- "--$B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--$B\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\npříliš žluťoučký kůň\r\n--$B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--$B--\r\n" > data/body_small.txt
{ printf -- "--$B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--$B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"; head -c 1048576 /dev/urandom; printf "\r\n--$B--\r\n"; } > data/body_1m.bin
{ printf -- "--$B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--$B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"; head -c 10485760 /dev/urandom; printf "\r\n--$B--\r\n"; } > data/body_10m.bin
CT="multipart/form-data; boundary=$B"
run_ab() { # <label> <bodyfile> <n> <c> [extra header]
    local label=$1 body=$2 n=$3 c=$4 extra=${5:-}
    local out
    out=$(ab -q -n "$n" -c "$c" -p "$body" -T "$CT" -H "Host: test.local" ${extra:+-H "$extra"} "$URL" 2>&1)
    printf "  %-34s rps=%-8s mean=%-8s p50=%-6s p95=%-6s p99=%-6s non2xx=%s\n" "$label" \
        "$(echo "$out" | awk '/Requests per second/{print $4}')" "$(echo "$out" | awk '/Time per request.*\(mean\)$/{print $4"ms"}')" \
        "$(echo "$out" | awk '/^ *50%/{print $2}')" "$(echo "$out" | awk '/^ *95%/{print $2}')" "$(echo "$out" | awk '/^ *99%/{print $2}')" \
        "$(echo "$out" | awk '/Non-2xx/{print $3}')"
}
echo "== ab: small multipart (3 fields), n=$N c=$C"
run_ab "direct (token)" data/body_small.txt "$N" "$C" "X-Multipart-Guard: $TOKEN"
run_ab "via guard" data/body_small.txt "$N" "$C"
echo "== ab: 1 MB file, n=400 c=10"
run_ab "direct (token)" data/body_1m.bin 400 10 "X-Multipart-Guard: $TOKEN"
run_ab "via guard" data/body_1m.bin 400 10
echo "== ab: 10 MB file, n=60 c=6"
run_ab "direct (token)" data/body_10m.bin 60 6 "X-Multipart-Guard: $TOKEN"
run_ab "via guard" data/body_10m.bin 60 6
if command -v wrk >/dev/null; then
cat > data/wrk-post.lua <<LUA
wrk.method = "POST"
wrk.headers["Content-Type"] = "$CT"
wrk.headers["Host"] = "test.local"
local f = io.open("data/body_small.txt", "rb"); wrk.body = f:read("*a"); f:close()
LUA
cat > data/wrk-post-token.lua <<LUA
wrk.method = "POST"
wrk.headers["Content-Type"] = "$CT"
wrk.headers["Host"] = "test.local"
wrk.headers["X-Multipart-Guard"] = "$TOKEN"
local f = io.open("data/body_small.txt", "rb"); wrk.body = f:read("*a"); f:close()
LUA
echo "== wrk: small multipart, 15 s, 4 threads, 32 connections"
echo "  direct (token):"; wrk -t4 -c32 -d15s -s data/wrk-post-token.lua "$URL" 2>&1 | grep -E 'Requests/sec|Latency|Non-2xx' | sed 's/^/    /'
echo "  via guard:";    wrk -t4 -c32 -d15s -s data/wrk-post.lua "$URL" 2>&1 | grep -E 'Requests/sec|Latency|Non-2xx' | sed 's/^/    /'
fi
echo "== guard resources"; ps -o rss=,vsz=,nlwp= -p "$(cat guard.pid)" | awk '{printf "  RSS=%d MB threads=%d\n", $1/1024, $3}'
