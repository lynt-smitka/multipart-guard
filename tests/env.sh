#!/bin/bash
# Local test environment: own nginx (8081/8443/8082/8083) + php-fpm (9001) + guard (8090). Runs as root (test only).
# Usage: tests/env.sh start [log|sanitize|block] | stop | restart-guard <mode> | status
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
RUN=$HERE/run
WWW=$HERE/www
BIN=$ROOT/dist/multipart-guard
TOKEN=${GUARD_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef}
MODE=${2:-log}
MAXBODY=${GUARD_MAX_BODY:-256M}

render() { sed -e "s#__RUN__#$RUN#g" -e "s#__WWW__#$WWW#g" -e "s#__TOKEN__#$TOKEN#g" -e "s#__MODE__#$MODE#g" -e "s#__MAXBODY__#$MAXBODY#g" -e "s#__ENABLED__#1#g" "$1"; }

start_guard() {
    render "$HERE/guard.conf.tmpl" > "$RUN/guard.conf"
    "$BIN" -config "$RUN/guard.conf" >"$RUN/guard.stderr" 2>&1 &
    echo $! > "$RUN/guard.pid"
    sleep 0.3
    kill -0 "$(cat "$RUN/guard.pid")" 2>/dev/null || { echo "guard did not start:"; cat "$RUN/guard.stderr"; exit 1; }
}
stop_guard() {
    [ -f "$RUN/guard.pid" ] && kill "$(cat "$RUN/guard.pid")" 2>/dev/null
    pkill -f "$BIN -config $RUN/guard.conf" 2>/dev/null
    rm -f "$RUN/guard.pid"
    for i in 1 2 3 4 5 6 7 8 9 10; do ss -ltn | grep -q ':8090 ' || break; sleep 0.3; done
}

case "${1:-}" in
start)
    mkdir -p "$RUN"/{conf.d,body,proxy,fcgi,upload,spool}
    [ -f "$RUN/key.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout "$RUN/key.pem" -out "$RUN/cert.pem" -days 30 -subj '/CN=test.local' 2>/dev/null
    render "$HERE/nginx.conf.tmpl" > "$RUN/nginx.conf"
    sed -e "s/__TOKEN__/$TOKEN/" "$ROOT/nginx/multipart-guard.conf" > "$RUN/conf.d/00-multipart-guard.conf"
    cp "$ROOT/nginx/multipart-guard-proxy.conf" "$RUN/multipart-guard-proxy.conf"
    { sed -e 's#/etc/nginx/multipart-guard-proxy.conf#'"$RUN"'/multipart-guard-proxy.conf#' "$ROOT/nginx/server-snippet.conf"; render "$HERE/php.tmpl" | grep -v '^__SNIPPET__'; } > "$RUN/php"
    { sed -e 's#/etc/nginx/multipart-guard-proxy.conf#'"$RUN"'/multipart-guard-proxy.conf#' "$ROOT/nginx/location-snippet.conf"; render "$HERE/php.load.tmpl" | grep -v '^__SNIPPET__'; } > "$RUN/php.load"
    render "$HERE/php-fpm.conf.tmpl" > "$RUN/php-fpm.conf"
    true
    php-fpm8.4 -R -y "$RUN/php-fpm.conf" || exit 1
    nginx -t -c "$RUN/nginx.conf" -p "$RUN" >/dev/null 2>&1 || { nginx -t -c "$RUN/nginx.conf" -p "$RUN"; exit 1; }
    nginx -c "$RUN/nginx.conf" -p "$RUN" || exit 1
    start_guard
    echo "running: nginx 8081/8443(test.local) 8082(plain.local) 8083(load.local), php-fpm 9001, guard 8090 mode=$MODE"
    ;;
stop)
    stop_guard
    [ -f "$RUN/nginx.pid" ] && nginx -s quit -c "$RUN/nginx.conf" -p "$RUN" 2>/dev/null
    [ -f "$RUN/php-fpm.pid" ] && kill "$(cat "$RUN/php-fpm.pid")" 2>/dev/null
    sleep 0.5; echo "stopped"
    ;;
restart-guard)
    stop_guard; sleep 0.3; start_guard; echo "guard mode=$MODE"
    ;;
reload-nginx)
    nginx -t -c "$RUN/nginx.conf" -p "$RUN" && nginx -s reload -c "$RUN/nginx.conf" -p "$RUN"
    ;;
status)
    ss -ltnp | grep -E ':(8081|8443|8082|8083|9001|8090)\b'
    ;;
*) echo "usage: $0 start [mode] | stop | restart-guard <mode> | reload-nginx | status"; exit 1;;
esac
