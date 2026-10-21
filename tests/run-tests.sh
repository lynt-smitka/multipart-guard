#!/bin/bash
# Functional tests against the local environment (tests/env.sh). Run: tests/run-tests.sh
# Compares what PHP sees for a direct request (with token = bypasses the guard) and via the guard.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
RUN=$HERE/run
TOKEN=${GUARD_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef}
BASE=https://127.0.0.1:8443
HOST=test.local
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; }
cd "$RUN" || exit 1
mkdir -p data
[ -f data/f_empty ] || : > data/f_empty
[ -f data/f_small.bin ] || printf 'abc\r\n--boundary-like\r\n\x00\x01\xff' > data/f_small.bin
[ -f data/f_text.txt ] || printf 'řádek1\r\nřádek2\n"quote" \\ back\n' > data/f_text.txt
[ -f data/f_60m.bin ] || head -c 62914560 /dev/urandom > data/f_60m.bin
[ -f data/f_2m.bin ] || head -c 2097152 /dev/urandom > data/f_2m.bin

# both <name> <url> <curl args...>: direct (with token) vs guard, compares JSON
both() {
    local name=$1 url=$2; shift 2
    curl -sk -o "out_base.json" -w '%{http_code}' -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" "$@" "$url" > base.code
    curl -sk -o "out_guard.json" -w '%{http_code}' -H "Host: $HOST" "$@" "$url" > guard.code
    if [ "$(cat base.code)" != "$(cat guard.code)" ]; then fail "$name" "status baseline=$(cat base.code) guard=$(cat guard.code)"; return; fi
    if d=$(python3 -I "$HERE/compare.py" out_base.json out_guard.json 2>&1); then ok "$name"; else fail "$name" "$d"; fi
}

echo "== mode sanitize"
"$HERE/env.sh" restart-guard sanitize >/dev/null || exit 1

both "non-ASCII text, CRLF, quotes, name[] arrays" "$BASE/dump.php?a=1&b=%C4%9B" \
    -F 'text=příliš žluťoučký kůň' -F $'crlf=řádek1\r\nřádek2\rřádek3\nřádek4' -F 'q="quoted" \ back\slash' \
    -F 'pole[]=1' -F 'pole[]=2' -F 'pole[x]=3' -F 'empty=' -F 'name="a"b=c'
both "multiple files, empty file, binary with --, non-ASCII filename" "$BASE/dump.php" \
    -F 'f1=@data/f_small.bin;filename=č ěš ř.bin' -F 'f2=@data/f_text.txt;type=text/plain' -F 'f3=@data/f_empty' \
    -F 'files[]=@data/f_small.bin' -F 'files[]=@data/f_text.txt' -F 'noname=@data/f_small.bin;filename=' -F 'text=x'
both "filename with quote and backslash" "$BASE/dump.php" -F 'f=@data/f_small.bin;filename=a"b\c.bin'
both "60 MB file" "$BASE/dump.php" -F 'big=@data/f_60m.bin' -F 'x=1'
both "plain http vhost on 8082" "http://127.0.0.1:8082/dump.php" -F 'a=1' -F 'f=@data/f_text.txt'
both "location-snippet variant (if+proxy_pass, 8083)" "http://127.0.0.1:8083/dump.php" -F 'a=1' -F 'f=@data/f_text.txt'
both "HTTP/1.1 instead of HTTP/2" "$BASE/dump.php" --http1.1 -F 'a=1' -F 'f=@data/f_text.txt'
both "chunked body (no Content-Length)" "$BASE/dump.php" -H 'Transfer-Encoding: chunked' -F 'a=1' -F 'f=@data/f_small.bin'
both "headers: Cookie, Authorization, XFF, Accept-Encoding" "$BASE/dump.php" --compressed -F 'a=1' -H 'Cookie: wordpress_logged_in=1; x=y' \
    -H 'Authorization: Basic dXNlcjpwYXNz' -H 'X-Forwarded-For: 1.2.3.4, 5.6.7.8' -H 'Accept-Encoding: gzip, br' -H 'X-Custom: ěšč'
both "PUT multipart" "$BASE/dump.php" -X PUT -F 'a=1'
both "empty multipart body" "$BASE/dump.php" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary ''

# upload progress: direct has it, guard drops it, the rest is identical
curl -sk -o up_base.json -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -F 'PHP_SESSION_UPLOAD_PROGRESS=abc' -F 'a=1' -F 'f=@data/f_text.txt' "$BASE/dump.php"
curl -sk -o up_guard.json -H "Host: $HOST" -F 'PHP_SESSION_UPLOAD_PROGRESS=abc' -F 'a=1' -F 'f=@data/f_text.txt' -F 'php_session_x=1' "$BASE/dump.php"
if python3 -I -c '
import json,sys; a=json.load(open("up_base.json")); b=json.load(open("up_guard.json"))
assert "PHP_SESSION_UPLOAD_PROGRESS" in a["post"], "direct request lacks upload progress"
assert "PHP_SESSION_UPLOAD_PROGRESS" not in b["post"] and "php_session_x" not in b["post"], b["post"]
a["post"].pop("PHP_SESSION_UPLOAD_PROGRESS"); assert a["post"]==b["post"] and a["files"]==b["files"]'; then ok "PHP_SESSION_UPLOAD_PROGRESS dropped, rest unchanged"; else fail "upload progress"; fi

# realip: hit the guard directly like nginx does (first pass) with X-Guard-Orig-IP
r=$(curl -s -H "Host: $HOST" -H 'X-Guard-Orig-IP: 203.0.113.5' -H 'X-Guard-Orig-Proto: https' -H 'X-Guard-Orig-Port: 8443' -F 'a=1' http://127.0.0.1:8090/dump.php | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["server"]["REMOTE_ADDR"], d["server"]["HTTPS"], d["server"]["SERVER_PORT"])')
[ "$r" = "203.0.113.5 on 8443" ] && ok "realip: PHP sees the original IP, HTTPS=on, port 8443" || fail "realip" "$r"
# spoofing: the client sends X-Guard-Orig-IP itself → nginx overwrites it with $remote_addr
# (the client must come from an address other than 127.0.0.1, which nginx trusts)
r=$(curl -sk --interface 127.0.0.2 -H "Host: $HOST" -H 'X-Guard-Orig-IP: 203.0.113.9' -F 'a=1' "$BASE/dump.php" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["server"]["REMOTE_ADDR"])')
[ "$r" = "127.0.0.2" ] && ok "client-supplied X-Guard-Orig-IP is ignored" || fail "spoof" "$r"
# wrong client token → goes through the guard (upload progress disappears)
r=$(curl -sk -H "Host: $HOST" -H 'X-Multipart-Guard: wrongtoken' -F 'PHP_SESSION_UPLOAD_PROGRESS=1' "$BASE/dump.php" | python3 -I -c 'import json,sys; print("PHP_SESSION_UPLOAD_PROGRESS" in json.load(sys.stdin)["post"])')
[ "$r" = "False" ] && ok "wrong client token = goes through the guard" || fail "wrong token" "$r"

# guard passthrough (non-multipart) – directly to the guard, compared with direct
for ct in 'application/json' 'application/x-www-form-urlencoded'; do
    body='{"a":1,"č":"ě"}'; [ "$ct" = application/x-www-form-urlencoded ] && body='a=1&%C4%8D=%C4%9B&p[]=1'
    curl -sk -o pt_base.json -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -H "Content-Type: $ct" --data-binary "$body" "$BASE/dump.php"
    curl -s -o pt_guard.json -H "Host: $HOST" -H 'X-Guard-Orig-IP: 127.0.0.1' -H 'X-Guard-Orig-Proto: https' -H 'X-Guard-Orig-Port: 8443' -H "Content-Type: $ct" --data-binary "$body" http://127.0.0.1:8090/dump.php
    if d=$(python3 -I "$HERE/compare.py" pt_base.json pt_guard.json 2>&1) && python3 -I -c 'import json; a=json.load(open("pt_base.json")); b=json.load(open("pt_guard.json")); assert a["input_md5"]==b["input_md5"] and a["input_len"]>0'; then ok "passthrough $ct unchanged"; else fail "passthrough $ct" "$d"; fi
done
r=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'X-Guard-Orig-Proto: https' -H 'X-Guard-Orig-Port: 8443' http://127.0.0.1:8090/dump.php?status=204)
[ "$r" = "204" ] && ok "passthrough GET" || fail "passthrough GET" "$r"

# response 1:1: status, headers, cookie, large body
for st in 404 500 302; do
    r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?status=$st")
    [ "$r" = "$st" ] && ok "response status $st passes" || fail "status $st" "$r"
done
curl -sk -D hdr_base.txt -o /dev/null -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?cookie=1"
curl -sk -D hdr_guard.txt -o /dev/null -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?cookie=1"
if diff <(grep -iE '^(set-cookie|x-custom|content-type):' hdr_base.txt | sort) <(grep -iE '^(set-cookie|x-custom|content-type):' hdr_guard.txt | sort) >/dev/null; then ok "response headers (Set-Cookie, X-Custom, Content-Type) 1:1"; else fail "response headers" "$(diff hdr_base.txt hdr_guard.txt)"; fi
a=$(curl -sk -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?big=8" | tail -c 8388608 | md5sum); b=$(curl -sk -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?big=8" | tail -c 8388608 | md5sum)
[ "$a" = "$b" ] && ok "8 MB response identical" || fail "large response" "$a $b"
a=$(curl -sk --compressed -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?big=2" | tail -c 2097152 | md5sum); b=$(curl -sk --compressed -H "Host: $HOST" -F 'a=1' "$BASE/dump.php?big=2" | tail -c 2097152 | md5sum)
[ "$a" = "$b" ] && ok "gzip response identical" || fail "gzip response" "$a $b"

# rejections in sanitize mode
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=ab"c' --data-binary 'x' "$BASE/dump.php")
[ "$r" = "400" ] && ok "invalid boundary → 400" || fail "invalid boundary" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary $'--abc\r\nContent-Disposition: form-data; name="x"\r\n\r\ntrunc' "$BASE/dump.php")
[ "$r" = "400" ] && ok "truncated body → 400" || fail "truncated body" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary $'--abc\r\nContent-Disposition: form-data; name="x"\r\nContent-Type: multipart/mixed; boundary=zz\r\n\r\nq\r\n--abc--\r\n' "$BASE/dump.php")
[ "$r" = "400" ] && ok "nested multipart → 400" || fail "nested multipart" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary $'--abc\r\nContent-Type: text/plain\r\n\r\nq\r\n--abc--\r\n' "$BASE/dump.php")
[ "$r" = "400" ] && ok "part without Content-Disposition → 400" || fail "no CD" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary $'--abc\r\nContent-Disposition: form-data; name="x"\r\nX-Evil: '"$(head -c 20000 /dev/zero | tr '\0' 'a')"$'\r\n\r\nq\r\n--abc--\r\n' "$BASE/dump.php")
[ "$r" = "400" ] && ok "20 kB part header → 400" || fail "long header" "$r"
# body limit (413) – guard with max_body 1M
GUARD_MAX_BODY=1M "$HERE/env.sh" restart-guard sanitize >/dev/null
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -F 'f=@data/f_2m.bin' "$BASE/dump.php")
[ "$r" = "413" ] && ok "body above max_body → 413" || fail "413" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Transfer-Encoding: chunked' -F 'f=@data/f_2m.bin' "$BASE/dump.php")
[ "$r" = "413" ] && ok "chunked body above max_body → 413" || fail "chunked 413" "$r"
"$HERE/env.sh" restart-guard sanitize >/dev/null

echo "== mode log"
"$HERE/env.sh" restart-guard log >/dev/null
r=$(curl -sk -H "Host: $HOST" -F 'PHP_SESSION_UPLOAD_PROGRESS=abc' -F 'a=1' "$BASE/dump.php" | python3 -I -c 'import json,sys; print("PHP_SESSION_UPLOAD_PROGRESS" in json.load(sys.stdin)["post"])')
[ "$r" = "True" ] && ok "log: original passes unchanged (upload progress kept)" || fail "log mode" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: multipart/form-data; boundary=abc' --data-binary $'--abc\r\nContent-Type: text/plain\r\n\r\nq\r\n--abc--\r\n' "$BASE/dump.php")
[ "$r" = "200" ] && ok "log: malformed body passes (only logged)" || fail "log malformed body" "$r"
both "log: 60 MB file" "$BASE/dump.php" -F 'big=@data/f_60m.bin'
grep -q '"action":"forward".*"dropped":\["PHP_SESSION_UPLOAD_PROGRESS"\]' guard.log && ok "log: finding written to the JSON log" || fail "log json"

echo "== mode block"
"$HERE/env.sh" restart-guard block >/dev/null
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -F 'a=1' "$BASE/dump.php")
[ "$r" = "403" ] && ok "block: multipart → 403" || fail "block" "$r"
r=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'Content-Type: application/json' --data '{}' "$BASE/dump.php")
[ "$r" = "200" ] && ok "block: JSON POST bypasses the guard" || fail "block json" "$r"

echo "== latency (200× small multipart POST, sanitize)"
"$HERE/env.sh" restart-guard sanitize >/dev/null
lat() { local extra=("$@"); local t=0; for i in $(seq 1 200); do t=$(echo "$t + $(curl -sk -o /dev/null -w '%{time_total}' "${extra[@]}" -H "Host: $HOST" -F 'a=1' -F 'b=ěšč' -F 'f=@data/f_text.txt' "$BASE/dump.php")" | bc -l); done; echo "scale=2; $t*1000/200" | bc -l; }
echo "  direct (token):  $(lat -H "X-Multipart-Guard: $TOKEN") ms"
echo "  via guard:       $(lat) ms"
t0=$(date +%s.%N); curl -sk -o /dev/null -H "X-Multipart-Guard: $TOKEN" -H "Host: $HOST" -F 'big=@data/f_60m.bin' "$BASE/dump.php"; t1=$(date +%s.%N); curl -sk -o /dev/null -H "Host: $HOST" -F 'big=@data/f_60m.bin' "$BASE/dump.php"; t2=$(date +%s.%N)
echo "  60 MB direct: $(echo "($t1-$t0)*1000/1" | bc) ms, via guard: $(echo "($t2-$t1)*1000/1" | bc) ms"

echo; echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
