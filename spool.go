package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// spool holds a request body: up to memLimit in memory, then in a temporary file
// (unlinked right after creation, so nothing is left on disk after a crash).
type spool struct {
	dir      string
	memLimit int64
	buf      bytes.Buffer
	f        *os.File
	size     int64
}

func newSpool(dir string, memLimit int64) *spool {
	return &spool{dir: dir, memLimit: memLimit}
}

func (s *spool) Write(p []byte) (int, error) {
	if s.f == nil && s.size+int64(len(p)) > s.memLimit {
		f, err := os.CreateTemp(s.dir, "body-*")
		if err != nil {
			return 0, fmt.Errorf("spool: %w", err)
		}
		os.Remove(f.Name())
		if _, err := f.Write(s.buf.Bytes()); err != nil {
			f.Close()
			return 0, fmt.Errorf("spool: %w", err)
		}
		s.buf = bytes.Buffer{}
		s.f = f
	}
	var n int
	var err error
	if s.f != nil {
		n, err = s.f.Write(p)
	} else {
		n, err = s.buf.Write(p)
	}
	s.size += int64(n)
	return n, err
}

func (s *spool) Size() int64 { return s.size }

// Reader returns a reader positioned at the start. Call once.
func (s *spool) Reader() (io.Reader, error) {
	if s.f != nil {
		if _, err := s.f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return s.f, nil
	}
	return bytes.NewReader(s.buf.Bytes()), nil
}

func (s *spool) Close() error {
	if s.f != nil {
		err := s.f.Close()
		s.f = nil
		return err
	}
	s.buf = bytes.Buffer{}
	return nil
}
