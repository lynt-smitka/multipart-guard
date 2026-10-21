package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Logger writes one JSON object per line. The file is reopened on SIGHUP (logrotate).
type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
	std  bool
}

func newLogger(path string) (*Logger, error) {
	l := &Logger{path: path}
	if err := l.reopen(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.path {
	case "", "stdout", "-":
		l.f, l.std = os.Stdout, true
		return nil
	case "stderr":
		l.f, l.std = os.Stderr, true
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		return err
	}
	if l.f != nil && !l.std {
		l.f.Close()
	}
	l.f, l.std = f, false
	return nil
}

// Entry is one log record. Empty fields are omitted.
type Entry struct {
	Time          string   `json:"ts"`
	Event         string   `json:"event"`            // request | info
	Mode          string   `json:"mode,omitempty"`   // log | sanitize | block
	Action        string   `json:"action,omitempty"` // passthrough | forward | sanitized | blocked | rejected
	IP            string   `json:"ip,omitempty"`
	Host          string   `json:"host,omitempty"`
	Method        string   `json:"method,omitempty"`
	URI           string   `json:"uri,omitempty"`
	Proto         string   `json:"proto,omitempty"`
	UserAgent     string   `json:"ua,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	BytesIn       int64    `json:"bytes_in,omitempty"`
	BytesOut      int64    `json:"bytes_out,omitempty"`
	Parts         int      `json:"parts,omitempty"`
	Files         int      `json:"files,omitempty"`
	Dropped       []string `json:"dropped,omitempty"`
	Issues        []string `json:"issues,omitempty"`
	Error         string   `json:"error,omitempty"`
	Status        int      `json:"status,omitempty"`
	DurationMs    float64  `json:"dur_ms,omitempty"`
	UpstreamMs    float64  `json:"upstream_ms,omitempty"`
	Msg           string   `json:"msg,omitempty"`
}

func (l *Logger) Log(e *Entry) {
	if e.Time == "" {
		e.Time = time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	l.f.Write(b)
	l.mu.Unlock()
}

func (l *Logger) Info(msg string) {
	l.Log(&Entry{Event: "info", Msg: msg})
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && !l.std {
		l.f.Close()
	}
}
