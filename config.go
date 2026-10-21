package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from a simple "key = value" file.
type Config struct {
	Listen string // where the guard listens (the web server sends multipart requests here)
	Mode   string // log | sanitize | block
	Token  string // secret sent back to the web server in X-Multipart-Guard

	UpstreamHost        string // where to send the sanitized request (the same web server), typically 127.0.0.1
	UpstreamPortHTTP    int    // port for requests that originally came over http
	UpstreamPortHTTPS   int    // port for requests that originally came over https (TLS, SNI = Host)
	UpstreamUseOrigPort bool   // honour X-Guard-Orig-Port if present
	UpstreamTLSVerify   bool   // verify the upstream certificate (pointless on loopback)

	MaxBody           int64 // maximum request body (413 above)
	MaxParts          int   // maximum number of parts
	MaxPartHeaderSize int   // maximum total header bytes per part
	MaxPartHeaders    int   // maximum number of header lines per part
	MaxNameLen        int   // maximum length of the "name" parameter
	MaxFilenameLen    int   // maximum length of the "filename" parameter
	MaxPartCTypeLen   int   // maximum length of a part's Content-Type

	SpoolDir    string // where large bodies are spooled
	SpoolMemory int64  // bodies up to this size stay in memory

	LogFile        string // JSON log path, or "stdout"/"stderr"
	LogPassthrough bool   // log non-multipart requests too
	PidFile        string

	RealIPHeaders    []string // headers set to the original client IP (for the web server's real-IP module on the second pass)
	DropNamePrefixes []string // parts whose name starts with one of these prefixes are dropped

	ReadHeaderTimeout time.Duration
	BodyTimeout       time.Duration // reading the body from the web server
	UpstreamTimeout   time.Duration // waiting for the application response
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

func defaultConfig() *Config {
	return &Config{
		Listen:              "127.0.0.1:8090",
		Mode:                "log",
		UpstreamHost:        "127.0.0.1",
		UpstreamPortHTTP:    80,
		UpstreamPortHTTPS:   443,
		UpstreamUseOrigPort: true,
		UpstreamTLSVerify:   false,
		MaxBody:             256 << 20,
		MaxParts:            1000,
		MaxPartHeaderSize:   8192,
		MaxPartHeaders:      8,
		MaxNameLen:          1024,
		MaxFilenameLen:      1024,
		MaxPartCTypeLen:     255,
		SpoolDir:            "/var/tmp/multipart-guard",
		SpoolMemory:         1 << 20,
		LogFile:             "stdout",
		LogPassthrough:      false,
		RealIPHeaders:       []string{"X-Guard-Orig-IP"},
		DropNamePrefixes:    []string{"PHP_SESSION"},
		ReadHeaderTimeout:   30 * time.Second,
		BodyTimeout:         600 * time.Second,
		UpstreamTimeout:     600 * time.Second,
		IdleTimeout:         75 * time.Second,
		ShutdownTimeout:     30 * time.Second,
	}
}

// parseSize understands 256M, 1G, 512k, 4096.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'k', 'K':
		mult = 1 << 10
		s = s[:len(s)-1]
	case 'm', 'M':
		mult = 1 << 20
		s = s[:len(s)-1]
	case 'g', 'G':
		mult = 1 << 30
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "yes", "on", "true":
		return true, nil
	case "0", "no", "off", "false":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

func parseDur(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

func parseList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadConfig reads the file and applies defaults for anything not set.
func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") {
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		key := strings.ToLower(strings.TrimSpace(raw[:eq]))
		val := strings.TrimSpace(raw[eq+1:])
		if err := cfg.set(key, val); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return cfg, nil
}

func (c *Config) set(key, val string) error {
	var err error
	switch key {
	case "listen":
		c.Listen = val
	case "mode":
		c.Mode = strings.ToLower(val)
	case "token":
		c.Token = val
	case "upstream_host":
		c.UpstreamHost = val
	case "upstream_port_http":
		c.UpstreamPortHTTP, err = strconv.Atoi(val)
	case "upstream_port_https":
		c.UpstreamPortHTTPS, err = strconv.Atoi(val)
	case "upstream_use_orig_port":
		c.UpstreamUseOrigPort, err = parseBool(val)
	case "upstream_tls_verify":
		c.UpstreamTLSVerify, err = parseBool(val)
	case "max_body":
		c.MaxBody, err = parseSize(val)
	case "max_parts":
		c.MaxParts, err = strconv.Atoi(val)
	case "max_part_header_size":
		var n int64
		n, err = parseSize(val)
		c.MaxPartHeaderSize = int(n)
	case "max_part_headers":
		c.MaxPartHeaders, err = strconv.Atoi(val)
	case "max_name_length":
		c.MaxNameLen, err = strconv.Atoi(val)
	case "max_filename_length":
		c.MaxFilenameLen, err = strconv.Atoi(val)
	case "max_part_content_type_length":
		c.MaxPartCTypeLen, err = strconv.Atoi(val)
	case "spool_dir":
		c.SpoolDir = val
	case "spool_memory":
		c.SpoolMemory, err = parseSize(val)
	case "log":
		c.LogFile = val
	case "log_passthrough":
		c.LogPassthrough, err = parseBool(val)
	case "pidfile":
		c.PidFile = val
	case "real_ip_headers":
		c.RealIPHeaders = parseList(val)
	case "drop_name_prefixes":
		c.DropNamePrefixes = parseList(val)
	case "read_header_timeout":
		c.ReadHeaderTimeout, err = parseDur(val)
	case "body_timeout":
		c.BodyTimeout, err = parseDur(val)
	case "upstream_timeout":
		c.UpstreamTimeout, err = parseDur(val)
	case "idle_timeout":
		c.IdleTimeout, err = parseDur(val)
	case "shutdown_timeout":
		c.ShutdownTimeout, err = parseDur(val)
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	if err != nil {
		return fmt.Errorf("%s: %v", key, err)
	}
	return nil
}

func (c *Config) validate() error {
	switch c.Mode {
	case "log", "sanitize", "block":
	default:
		return fmt.Errorf("mode must be log, sanitize or block (got %q)", c.Mode)
	}
	if len(c.Token) < 16 {
		return fmt.Errorf("token must be at least 16 characters (openssl rand -hex 24)")
	}
	for _, r := range c.Token {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("token may contain only printable ASCII without spaces")
		}
	}
	if c.UpstreamHost == "" {
		return fmt.Errorf("upstream_host must not be empty")
	}
	if _, err := url.Parse("http://" + c.UpstreamHost + ":80/"); err != nil {
		return fmt.Errorf("upstream_host: %v", err)
	}
	if c.MaxBody <= 0 || c.MaxParts <= 0 || c.MaxPartHeaderSize < 256 || c.MaxPartHeaders < 2 ||
		c.MaxNameLen < 1 || c.MaxFilenameLen < 1 || c.MaxPartCTypeLen < 8 {
		return fmt.Errorf("max_* limits must be positive (max_part_header_size >= 256, max_part_headers >= 2)")
	}
	if c.SpoolMemory < 0 {
		return fmt.Errorf("spool_memory must not be negative")
	}
	if len(c.RealIPHeaders) == 0 {
		return fmt.Errorf("real_ip_headers must not be empty")
	}
	for _, h := range c.RealIPHeaders {
		if !validHeaderName(h) {
			return fmt.Errorf("real_ip_headers: invalid header name %q", h)
		}
	}
	return nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
