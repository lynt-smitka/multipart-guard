# multipart-guard

Sanitizing proxy for `multipart/form-data` requests between nginx (or Caddy) and PHP-FPM.
The web server sends every multipart request to the guard first. The guard parses the body with a strict
parser, drops suspicious parts, rebuilds the body in canonical form and sends it back to the web server,
which then passes it to PHP. PHP never sees a non-standard multipart body.

Written in October 2026 as a mitigation for CVE-2026-109618/109619 (PHP multipart RCE) on servers without a
fix. It is a workaround, not a patch.

The code was generated with Claude Code (Anthropic) under human direction and review, and tested against
real traffic. Status: experimental. Run in `log` mode first.

## How it works

1. nginx matches `Content-Type: multipart/form-data` without a valid `X-Multipart-Guard` token and proxies
   the request to `127.0.0.1:8090` (body streamed, headers unchanged, plus `X-Guard-Orig-IP/Proto/Port`).
2. The guard parses the body. `name`, `filename` and the boundary are evaluated by ports of the PHP functions
   from `main/rfc1867.c`, so the guard sees what PHP would see. It checks boundary, part count, header size,
   name/filename length and control characters, duplicate headers, nested multipart. Parts whose name starts
   with `PHP_SESSION` are dropped.
3. The body is spooled (RAM up to 1 MB, otherwise an unlinked temp file) and rebuilt with a random boundary
   and canonical headers (`Content-Disposition`, optional `Content-Type`). Parse error: 400. Over
   `max_body`: 413. Nothing reaches PHP before the whole body is validated.
4. The request goes back to the web server with the original method, URI, headers, exact `Content-Length`
   and the token. HTTPS requests go over TLS on loopback with SNI = Host, so PHP sees `HTTPS=on`.
   The client IP travels in `X-Guard-Orig-IP` for the real-IP module.
5. The response is copied 1:1 to the client.

Modes: `log` (inspect only, forward the original body), `sanitize` (rebuild), `block` (403).

## Install

Static linux/amd64 binary, no dependencies, kernel 2.6.32+ (built with Go 1.23 for that reason).

```bash
./build.sh
useradd -r -s /sbin/nologin -d /var/lib/multipart-guard -M multipart-guard
install -m 0755 dist/multipart-guard /usr/local/sbin/multipart-guard
mkdir -p /etc/multipart-guard /var/log/multipart-guard && chown multipart-guard /var/log/multipart-guard
install -m 0640 -o root -g multipart-guard etc/config.example /etc/multipart-guard/config
sed -i "s/^token = .*/token = $(openssl rand -hex 24)/" /etc/multipart-guard/config
multipart-guard -config /etc/multipart-guard/config -check
install -m 0644 systemd/multipart-guard.service /etc/systemd/system/ && systemctl enable --now multipart-guard
install -m 0644 etc/logrotate /etc/logrotate.d/multipart-guard
```

Without systemd: `init/multipart-guard` + `pidfile = /var/run/multipart-guard/guard.pid` in the config.

### nginx

1. `nginx/multipart-guard.conf` → `/etc/nginx/conf.d/00-multipart-guard.conf`, replace `__TOKEN__`.
   If `nginx.conf` already has `real_ip_header` (e.g. `CF-Connecting-IP`), remove that line from the file
   and add the header to `real_ip_headers` in the guard config.
2. `nginx/multipart-guard-proxy.conf` → `/etc/nginx/`.
3. At the top of every `server {}` that serves PHP (`nginx/server-snippet.conf`):
   ```nginx
   if ($mg_to_guard) { return 418; }
   error_page 418 = @multipart_guard;
   location @multipart_guard { include /etc/nginx/multipart-guard-proxy.conf; proxy_pass http://multipart_guard; }
   ```
   `proxy_pass` is not allowed in a server-level `if`; the named location keeps method and body.
   Inside a `location {}` use `nginx/location-snippet.conf` instead.
4. `nginx -t && nginx -s reload`. Disable: set `"1:0" 0;` in the conf.d file and reload.

Details that matter: the token map uses a regex key (a 48-char static key needs `map_hash_bucket_size`,
which cannot be set after another `map`); `Host` is `$http_host` with fallback to `$host` (empty over HTTP/3);
client headers are passed unchanged; every multipart request shows twice in the access log.

### Caddy

`caddy/Caddyfile-snippet`: `trusted_proxies` + `client_ip_headers X-Guard-Orig-IP`, a `handle` with
`reverse_proxy 127.0.0.1:8090`, and `env REMOTE_ADDR {client_ip}` in `php_fastcgi`. Untested in production.

## Configuration

`/etc/multipart-guard/config`, `key = value`; all keys in `etc/config.example`. Main ones: `listen`, `mode`,
`token`, `upstream_host`/`upstream_port_http`/`upstream_port_https`, `real_ip_headers`, `max_body` (256M),
`max_parts` (1000), `max_part_header_size` (8k), `max_name_length`/`max_filename_length` (1024),
`drop_name_prefixes` (`PHP_SESSION`), `spool_dir`, `log`, `body_timeout`/`upstream_timeout` (600s).
SIGHUP reopens the log.

## Log

JSON lines: `ts`, `action` (`forward`|`sanitized`|`blocked`|`rejected`|`passthrough`), `ip`, `host`, `uri`,
`parts`, `files`, `dropped`, `issues`, `error`, `status`, `dur_ms`. In `log` mode `error` shows what
`sanitize` would reject.

## Tests

`tests/env.sh start sanitize` starts a private nginx + php-fpm + guard; `tests/run-tests.sh` compares
`$_POST`/`$_FILES`/`$_SERVER` of direct requests with requests through the guard (37 cases: non-ASCII,
CRLF, quotes, `name[]`, multiple/empty files, 60 MB file, chunked, HTTP/2, headers, rejections, modes).
`tests/bench.sh` runs `ab`/`wrk`. Overhead measured: about 0.3 ms per small form, 70 ms per 60 MB upload.

## Limitations

- Whole body is read before PHP gets it (nginx buffers before FastCGI anyway).
- Stricter than PHP: missing final boundary or odd boundaries are rejected in `sanitize`. Check `log` first.
- `php://input` for multipart is the rebuilt body.
- PHP sees `HTTP_X_MULTIPART_GUARD`; clear it with `fastcgi_param HTTP_X_MULTIPART_GUARD "";` if needed.
- Requests from 127.0.0.1 are trusted by realip on the first pass.

## License

MIT, Lynt services s.r.o.
