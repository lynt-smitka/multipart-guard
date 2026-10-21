package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"strings"
)

// errTooLarge signals that max_body was exceeded (→ 413).
var errTooLarge = errors.New("request body exceeds the limit")

// limitedBody reads at most max bytes and then returns errTooLarge (unlike io.LimitReader,
// which returns a silent EOF that the parser would take for the end of the body).
type limitedBody struct {
	r    io.Reader
	left int64
	n    int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	l.left -= int64(n)
	if l.left < 0 {
		return n, errTooLarge
	}
	return n, err
}

// ---------------------------------------------------------------------------
// Ports of helper functions from PHP main/rfc1867.c. The goal is to evaluate the field name,
// filename and boundary EXACTLY the way PHP does, so that the canonical output yields the same
// data in PHP as the original request would have.

func isCSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// phpSubstringConf = substring_conf(): drops backslashes before \\ and before the quote char.
func phpSubstringConf(s string, quote byte) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || (quote != 0 && s[i+1] == quote)) {
			i++
			b.WriteByte(s[i])
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// phpGetWord = php_ap_getword(): returns the word up to the stop char (quote-aware) and the rest.
func phpGetWord(line string, stop byte) (word, rest string) {
	pos := 0
	for pos < len(line) && line[pos] != stop {
		if q := line[pos]; q == '"' || q == '\'' {
			pos++
			for pos < len(line) && line[pos] != q {
				if line[pos] == '\\' && pos+1 < len(line) && line[pos+1] == q {
					pos += 2
				} else {
					pos++
				}
			}
			if pos < len(line) {
				pos++
			}
		} else {
			pos++
		}
	}
	if pos >= len(line) {
		return line, ""
	}
	word = line[:pos]
	for pos < len(line) && line[pos] == stop {
		pos++
	}
	return word, line[pos:]
}

// phpGetWordConf = php_ap_getword_conf(): a parameter value (quoted, or up to whitespace).
func phpGetWordConf(s string) string {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	s = s[i:]
	if s == "" {
		return ""
	}
	if q := s[0]; q == '"' || q == '\'' {
		end := 1
	lookForQuote:
		for end < len(s) && s[end] != q {
			if s[end] == '\\' && end+1 < len(s) && s[end+1] == q {
				end += 2
			} else {
				end++
			}
		}
		if end < len(s) && s[end] == q {
			var p byte
			if end+1 < len(s) {
				p = s[end+1]
			}
			if p != '\r' && p != '\n' && p != 0 {
				end++
				goto lookForQuote
			}
		}
		if end > len(s) {
			end = len(s)
		}
		return phpSubstringConf(s[1:end], q)
	}
	end := 0
	for end < len(s) && !isCSpace(s[end]) {
		end++
	}
	return phpSubstringConf(s[:end], 0)
}

// phpContentDisposition evaluates a Content-Disposition header the way PHP does:
// returns name/filename and whether each was present (PHP distinguishes NULL from "").
func phpContentDisposition(cd string) (name string, hasName bool, filename string, hasFilename bool) {
	i := 0
	for i < len(cd) && isCSpace(cd[i]) {
		i++
	}
	cd = cd[i:]
	for cd != "" {
		var pair string
		pair, cd = phpGetWord(cd, ';')
		for cd != "" && isCSpace(cd[0]) {
			cd = cd[1:]
		}
		if !strings.Contains(pair, "=") {
			continue
		}
		key, rest := phpGetWord(pair, '=')
		if strings.EqualFold(key, "name") {
			name, hasName = phpGetWordConf(rest), true
		} else if strings.EqualFold(key, "filename") {
			filename, hasFilename = phpGetWordConf(rest), true
		}
	}
	return
}

// phpBoundary extracts the boundary from Content-Type the way PHP's rfc1867 post handler does.
func phpBoundary(contentType string) (string, error) {
	ct := contentType
	idx := strings.Index(ct, "boundary")
	if idx < 0 {
		idx = strings.Index(strings.ToLower(ct), "boundary")
	}
	if idx < 0 {
		return "", errors.New("missing boundary in Content-Type")
	}
	rest := ct[idx:]
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return "", errors.New("missing boundary in Content-Type")
	}
	b := rest[eq+1:]
	if strings.HasPrefix(b, "\"") {
		b = b[1:]
		end := strings.IndexByte(b, '"')
		if end < 0 {
			return "", errors.New("invalid boundary in Content-Type")
		}
		b = b[:end]
	} else if end := strings.IndexAny(b, ",;"); end >= 0 {
		b = b[:end]
	}
	if b == "" {
		return "", errors.New("empty boundary")
	}
	return b, nil
}

// validBoundary checks the boundary against RFC 2046 (1–70 chars, allowed set, no trailing space).
func validBoundary(b string) error {
	if len(b) == 0 || len(b) > 70 {
		return fmt.Errorf("boundary length %d outside 1–70", len(b))
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("'()+_,-./:=? ", c) >= 0:
		default:
			return fmt.Errorf("boundary contains forbidden byte 0x%02x", c)
		}
	}
	if b[len(b)-1] == ' ' {
		return errors.New("boundary ends with a space")
	}
	return nil
}

func hasCtl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// quoteParam writes a value in double quotes so that PHP (substring_conf) reads it back unchanged.
func quoteParam(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		if v[i] == '"' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('"')
	return b.String()
}

func newBoundary() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "----MultipartGuard" + hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------

// Limits are the strict parser limits.
type Limits struct {
	MaxParts          int
	MaxPartHeaderSize int
	MaxPartHeaders    int
	MaxNameLen        int
	MaxFilenameLen    int
	MaxCTypeLen       int
	DropNamePrefixes  []string
}

// Report is the result of processing one multipart body.
type Report struct {
	Parts    int
	Files    int
	BytesOut int64
	Dropped  []string // dropped parts (name)
	Issues   []string // tolerated anomalies
	Err      error    // fatal error: 400 in sanitize mode (413 for errTooLarge)
}

func (r *Report) issue(format string, a ...interface{}) {
	if len(r.Issues) < 50 {
		r.Issues = append(r.Issues, fmt.Sprintf(format, a...))
	}
}

var allowedPartHeaders = map[string]bool{
	"Content-Disposition":       true,
	"Content-Type":              true,
	"Content-Transfer-Encoding": true, // ignored by PHP, not emitted in canonical output
	"Content-Length":            true, // sent by some clients, ignored by PHP
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// processMultipart streams through the body using the original boundary. If out != nil,
// it writes the body re-assembled with newBound and canonical part headers into out.
// After a fatal error the contents of out are unusable (the caller discards them).
func processMultipart(body io.Reader, boundary string, out io.Writer, newBound string, lim *Limits) *Report {
	rep := &Report{}
	if err := validBoundary(boundary); err != nil {
		rep.Err = err
		return rep
	}
	counted := &limitedBody{r: body, left: 1<<62 - 1}
	mr := multipart.NewReader(counted, boundary)

	var cw *countingWriter
	var w *bufio.Writer
	if out != nil {
		cw = &countingWriter{w: out}
		w = bufio.NewWriterSize(cw, 64<<10)
	}
	buf := make([]byte, 64<<10)
	fatal := func(err error) *Report {
		rep.Err = err
		return rep
	}

	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return fatal(errTooLarge)
			}
			if counted.n == 0 {
				// empty body: PHP treats it as a form without fields
				rep.issue("empty body")
				break
			}
			return fatal(fmt.Errorf("part %d: %v", rep.Parts+1, err))
		}
		rep.Parts++
		idx := rep.Parts
		if idx > lim.MaxParts {
			return fatal(fmt.Errorf("too many parts (> %d)", lim.MaxParts))
		}

		nh, hsize := 0, 0
		for k, vs := range p.Header {
			nh += len(vs)
			for _, v := range vs {
				hsize += len(k) + len(v) + 4
			}
			if !allowedPartHeaders[k] {
				rep.issue("part %d: unknown header %s (dropped)", idx, k)
			}
		}
		if nh > lim.MaxPartHeaders {
			return fatal(fmt.Errorf("part %d: too many headers (%d)", idx, nh))
		}
		if hsize > lim.MaxPartHeaderSize {
			return fatal(fmt.Errorf("part %d: headers too long (%d B)", idx, hsize))
		}

		cds := p.Header.Values("Content-Disposition")
		if len(cds) == 0 {
			return fatal(fmt.Errorf("part %d: missing Content-Disposition", idx))
		}
		if len(cds) > 1 {
			return fatal(fmt.Errorf("part %d: multiple Content-Disposition headers", idx))
		}
		cd := cds[0]
		if hasCtl(cd) {
			return fatal(fmt.Errorf("part %d: control characters in Content-Disposition", idx))
		}
		dispType, _ := phpGetWord(cd, ';')
		if !strings.EqualFold(strings.TrimSpace(dispType), "form-data") {
			rep.issue("part %d: disposition %q instead of form-data", idx, truncate(dispType, 40))
		}
		name, hasName, filename, hasFilename := phpContentDisposition(cd)
		if !hasName && !hasFilename {
			return fatal(fmt.Errorf("part %d: Content-Disposition without name and filename", idx))
		}
		if hasName {
			if len(name) > lim.MaxNameLen {
				return fatal(fmt.Errorf("part %d: name longer than %d", idx, lim.MaxNameLen))
			}
			if hasCtl(name) {
				return fatal(fmt.Errorf("part %d: control characters in name", idx))
			}
			if hasFilename && name == "" {
				rep.issue("part %d: file with empty name", idx)
			}
		} else {
			rep.issue("part %d: file without name (PHP assigns a numeric index)", idx)
		}
		if hasFilename {
			if len(filename) > lim.MaxFilenameLen {
				return fatal(fmt.Errorf("part %d: filename longer than %d", idx, lim.MaxFilenameLen))
			}
			if hasCtl(filename) {
				return fatal(fmt.Errorf("part %d: control characters in filename", idx))
			}
		}
		if hasName {
			for _, pre := range lim.DropNamePrefixes {
				if len(name) >= len(pre) && strings.EqualFold(name[:len(pre)], pre) {
					rep.Dropped = append(rep.Dropped, truncate(name, 80))
					if _, err := io.CopyBuffer(io.Discard, p, buf); err != nil {
						return fatal(wrapRead(idx, err))
					}
					p = nil
					break
				}
			}
			if p == nil {
				continue
			}
		}

		cts := p.Header.Values("Content-Type")
		ctype := ""
		if len(cts) > 1 {
			return fatal(fmt.Errorf("part %d: multiple Content-Type headers", idx))
		}
		if len(cts) == 1 {
			ctype = cts[0]
			if len(ctype) > lim.MaxCTypeLen || !printableASCII(ctype) {
				return fatal(fmt.Errorf("part %d: invalid part Content-Type", idx))
			}
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ctype)), "multipart/") {
				return fatal(fmt.Errorf("part %d: nested multipart", idx))
			}
		}
		if hasFilename {
			rep.Files++
		}

		if w == nil {
			if _, err := io.CopyBuffer(io.Discard, p, buf); err != nil {
				return fatal(wrapRead(idx, err))
			}
			continue
		}

		canon := "form-data"
		if hasName {
			canon += "; name=" + quoteParam(name)
		}
		if hasFilename {
			canon += "; filename=" + quoteParam(filename)
		}
		n2, hn2, f2, hf2 := phpContentDisposition(canon)
		if n2 != name || hn2 != hasName || f2 != filename || hf2 != hasFilename {
			return fatal(fmt.Errorf("part %d: name/filename cannot be written canonically", idx))
		}
		w.WriteString("--")
		w.WriteString(newBound)
		w.WriteString("\r\nContent-Disposition: ")
		w.WriteString(canon)
		w.WriteString("\r\n")
		if len(cts) == 1 {
			w.WriteString("Content-Type: ")
			w.WriteString(ctype)
			w.WriteString("\r\n")
		}
		w.WriteString("\r\n")
		if _, err := io.CopyBuffer(w, p, buf); err != nil {
			if errors.Is(err, errTooLarge) {
				return fatal(errTooLarge)
			}
			return fatal(wrapRead(idx, err))
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return fatal(fmt.Errorf("spool write: %v", err))
		}
	}

	if w != nil {
		w.WriteString("--")
		w.WriteString(newBound)
		w.WriteString("--\r\n")
		if err := w.Flush(); err != nil {
			return fatal(fmt.Errorf("spool write: %v", err))
		}
		rep.BytesOut = cw.n
	}
	return rep
}

func wrapRead(idx int, err error) error {
	if errors.Is(err, errTooLarge) {
		return errTooLarge
	}
	return fmt.Errorf("part %d: reading body: %v", idx, err)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
