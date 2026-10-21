package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Guard is the HTTP handler: it parses a multipart request, optionally sanitizes it and forwards it upstream.
type Guard struct {
	cfg       *Config
	log       *Logger
	transport *http.Transport
	limits    *Limits
	inflight  int64
}

func newGuard(cfg *Config, lg *Logger) *Guard {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		// The URL carries the original Host (for SNI and a per-host connection pool), but the connection always goes to upstream_host.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.UpstreamHost, port))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !cfg.UpstreamTLSVerify, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.UpstreamTimeout,
		ExpectContinueTimeout: 0,
		DisableCompression:    true,
	}
	return &Guard{
		cfg:       cfg,
		log:       lg,
		transport: tr,
		limits: &Limits{
			MaxParts:          cfg.MaxParts,
			MaxPartHeaderSize: cfg.MaxPartHeaderSize,
			MaxPartHeaders:    cfg.MaxPartHeaders,
			MaxNameLen:        cfg.MaxNameLen,
			MaxFilenameLen:    cfg.MaxFilenameLen,
			MaxCTypeLen:       cfg.MaxPartCTypeLen,
			DropNamePrefixes:  cfg.DropNamePrefixes,
		},
	}
}

var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Expect":              true,
}

// isMultipart mirrors PHP sapi_read_post_data(): Content-Type is cut at the first ';', ',' or space,
// lower-cased and compared with "multipart/form-data". PHP therefore treats
// "multipart/form-data, boundary=X", "multipart/form-data boundary=X" and "MULTIPART/Form-Data;boundary=X"
// as multipart, but not "multipart/form-datax; boundary=X" (PHP would not parse that at all → passthrough).
func isMultipart(ct string) bool {
	ct = strings.TrimLeft(ct, " \t")
	if i := strings.IndexAny(ct, ";, "); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(ct, "multipart/form-data")
}

func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Guard-Orig-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&g.inflight, 1)
	defer atomic.AddInt64(&g.inflight, -1)

	start := time.Now()
	e := &Entry{
		Event:         "request",
		Mode:          g.cfg.Mode,
		IP:            clientIP(r),
		Host:          r.Host,
		Method:        r.Method,
		URI:           truncate(r.RequestURI, 512),
		Proto:         r.Header.Get("X-Guard-Orig-Proto"),
		UserAgent:     truncate(r.UserAgent(), 200),
		ContentLength: r.ContentLength,
	}
	ct := r.Header.Get("Content-Type")

	if !isMultipart(ct) {
		e.Action = "passthrough"
		status, _, err := g.forward(w, r, r.Body, r.ContentLength, ct, e)
		e.Status = status
		if err != nil {
			e.Error = err.Error()
		}
		e.DurationMs = ms(start)
		if g.cfg.LogPassthrough || err != nil {
			g.log.Log(e)
		}
		return
	}
	e.ContentType = truncate(ct, 200)

	if g.cfg.Mode == "block" {
		e.Action = "blocked"
		e.Status = http.StatusForbidden
		http.Error(w, "Multipart requests are temporarily disabled.", http.StatusForbidden)
		e.DurationMs = ms(start)
		g.log.Log(e)
		return
	}
	if r.ContentLength > g.cfg.MaxBody {
		g.reject(w, e, http.StatusRequestEntityTooLarge, "Request body too large.", start, errTooLarge)
		return
	}

	sanitize := g.cfg.Mode == "sanitize"
	boundary, berr := phpBoundary(ct)
	if berr == nil {
		berr = validBoundary(boundary)
	}
	if berr != nil && sanitize {
		g.reject(w, e, http.StatusBadRequest, "Malformed multipart/form-data request.", start, berr)
		return
	}

	sp := newSpool(g.cfg.SpoolDir, g.cfg.SpoolMemory)
	defer sp.Close()
	body := &limitedBody{r: r.Body, left: g.cfg.MaxBody}

	var rep *Report
	outCT := ct
	if sanitize {
		nb := newBoundary()
		rep = processMultipart(body, boundary, sp, nb, g.limits)
		if rep.Err != nil {
			g.fillReport(e, rep)
			if errors.Is(rep.Err, errTooLarge) {
				g.reject(w, e, http.StatusRequestEntityTooLarge, "Request body too large.", start, rep.Err)
			} else {
				g.reject(w, e, http.StatusBadRequest, "Malformed multipart/form-data request.", start, rep.Err)
			}
			return
		}
		outCT = "multipart/form-data; boundary=" + nb
		e.Action = "sanitized"
	} else {
		// log mode: the body is only inspected, the ORIGINAL goes on
		tee := io.TeeReader(body, sp)
		if berr != nil {
			rep = &Report{Err: berr}
		} else {
			rep = processMultipart(tee, boundary, nil, "", g.limits)
		}
		// read the rest (the parser may have stopped early) so the spool is complete
		if _, err := io.Copy(io.Discard, tee); err != nil {
			g.fillReport(e, rep)
			if errors.Is(err, errTooLarge) {
				g.reject(w, e, http.StatusRequestEntityTooLarge, "Request body too large.", start, err)
			} else {
				g.reject(w, e, http.StatusBadRequest, "Error reading request body.", start, err)
			}
			return
		}
		if rep.Err != nil && errors.Is(rep.Err, errTooLarge) {
			g.fillReport(e, rep)
			g.reject(w, e, http.StatusRequestEntityTooLarge, "Request body too large.", start, rep.Err)
			return
		}
		e.Action = "forward"
	}
	g.fillReport(e, rep)
	e.BytesIn = body.n

	rd, err := sp.Reader()
	if err != nil {
		g.reject(w, e, http.StatusInternalServerError, "Internal error.", start, err)
		return
	}
	status, upMs, ferr := g.forward(w, r, io.NopCloser(rd), sp.Size(), outCT, e)
	e.Status = status
	e.UpstreamMs = upMs
	e.BytesOut = sp.Size()
	if ferr != nil {
		e.Error = ferr.Error()
	}
	e.DurationMs = ms(start)
	g.log.Log(e)
}

func (g *Guard) fillReport(e *Entry, rep *Report) {
	if rep == nil {
		return
	}
	e.Parts = rep.Parts
	e.Files = rep.Files
	e.Dropped = rep.Dropped
	e.Issues = rep.Issues
	if rep.Err != nil {
		e.Error = rep.Err.Error()
	}
}

func (g *Guard) reject(w http.ResponseWriter, e *Entry, status int, text string, start time.Time, err error) {
	e.Action = "rejected"
	e.Status = status
	if err != nil {
		e.Error = err.Error()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	io.WriteString(w, text+"\n")
	e.DurationMs = ms(start)
	g.log.Log(e)
}

// forward sends the request with the given body upstream and copies the response 1:1 to the client.
func (g *Guard) forward(w http.ResponseWriter, r *http.Request, body io.ReadCloser, length int64, ct string, e *Entry) (int, float64, error) {
	scheme := "http"
	port := g.cfg.UpstreamPortHTTP
	if strings.EqualFold(r.Header.Get("X-Guard-Orig-Proto"), "https") {
		scheme = "https"
		port = g.cfg.UpstreamPortHTTPS
	}
	if g.cfg.UpstreamUseOrigPort {
		if p, err := strconv.Atoi(r.Header.Get("X-Guard-Orig-Port")); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	host := r.Host
	if host == "" {
		host = g.cfg.UpstreamHost
	}
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	if hostOnly == "" || strings.ContainsAny(hostOnly, " /\\?#@") {
		w.Header().Set("Connection", "close")
		http.Error(w, "Bad Host header.", http.StatusBadRequest)
		return http.StatusBadRequest, 0, fmt.Errorf("invalid Host %q", host)
	}

	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(hostOnly, strconv.Itoa(port)), Opaque: r.RequestURI}
	if r.RequestURI == "" || r.RequestURI[0] != '/' {
		u.Opaque = r.URL.RequestURI()
	}
	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
	if err != nil {
		http.Error(w, "Bad request.", http.StatusBadRequest)
		return http.StatusBadRequest, 0, err
	}
	req.URL = u
	req.Host = host
	req.ContentLength = length
	if length == 0 {
		req.Body = http.NoBody
	}
	for k, vs := range r.Header {
		if hopByHop[k] || k == "Content-Length" || k == "Content-Type" || k == "X-Multipart-Guard" {
			continue
		}
		req.Header[k] = vs
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("X-Multipart-Guard", g.cfg.Token)
	ip := clientIP(r)
	for _, h := range g.cfg.RealIPHeaders {
		req.Header.Set(h, ip)
	}

	t0 := time.Now()
	resp, err := g.transport.RoundTrip(req)
	upMs := ms(t0)
	if err != nil {
		status := http.StatusBadGateway
		if ctx.Err() != nil {
			status = 499
		} else if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			status = http.StatusGatewayTimeout
		}
		if status != 499 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Connection", "close")
			w.WriteHeader(status)
			io.WriteString(w, "Upstream error.\n")
		}
		return status, upMs, fmt.Errorf("upstream: %v", err)
	}
	defer resp.Body.Close()

	h := w.Header()
	for k, vs := range resp.Header {
		if hopByHop[k] {
			continue
		}
		h[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := copyFlush(w, resp.Body); err != nil {
		return resp.StatusCode, upMs, fmt.Errorf("copying response: %v", err)
	}
	return resp.StatusCode, upMs, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// copyFlush copies the response and flushes after every chunk (long-running scripts with progressive output).
func copyFlush(w http.ResponseWriter, r io.Reader) (int64, error) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if fl != nil {
				fl.Flush()
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func ms(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000
}
