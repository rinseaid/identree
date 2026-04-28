package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// RotationConfig controls size-based log rotation for file sinks.
type RotationConfig struct {
	MaxSize  int // max bytes before rotation (0 = no rotation)
	MaxFiles int // number of rotated files to keep (e.g. 5 → .1 through .5)
}

// JSONLogSink writes one JSON line per event to an io.Writer.
// "stdout" writes to os.Stdout; anything else is treated as a file path.
type JSONLogSink struct {
	mu       sync.Mutex
	w        io.Writer
	closer   io.Closer // nil when writing to stdout
	enc      *json.Encoder
	path     string         // empty when writing to stdout
	written  int            // bytes written to current file
	rotation RotationConfig // zero value disables rotation
}

// NewJSONLogSink creates a sink that writes JSON lines to dest.
// dest is "stdout" for os.Stdout, or a file path (parent dirs are created).
// An optional RotationConfig enables size-based log rotation for file sinks.
func NewJSONLogSink(dest string, rot ...RotationConfig) (*JSONLogSink, error) {
	var rc RotationConfig
	if len(rot) > 0 {
		rc = rot[0]
	}

	s := &JSONLogSink{rotation: rc}

	if dest == "stdout" {
		s.w = os.Stdout
		s.enc = json.NewEncoder(os.Stdout)
		s.enc.SetEscapeHTML(false)
		return s, nil
	}

	s.path = dest
	if err := s.openFile(); err != nil {
		return nil, err
	}

	// Seed written with current file size so rotation triggers correctly
	// when appending to an existing file.
	if info, err := os.Stat(dest); err == nil {
		s.written = int(info.Size())
	}

	return s, nil
}

// openFile opens (or re-opens) the log file at s.path.
func (s *JSONLogSink) openFile() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return fmt.Errorf("audit jsonlog: mkdir %s: %w", filepath.Dir(s.path), err)
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0640)
	if err != nil {
		return fmt.Errorf("audit jsonlog: open %s: %w", s.path, err)
	}
	s.w = f
	s.closer = f
	s.enc = json.NewEncoder(f)
	s.enc.SetEscapeHTML(false)
	s.written = 0
	return nil
}

func (s *JSONLogSink) Name() string { return "jsonlog" }

func (s *JSONLogSink) Emit(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enc.Encode(e); err != nil {
		return err
	}

	// Track bytes and check rotation threshold for file sinks.
	if s.path != "" && s.rotation.MaxSize > 0 {
		b, _ := json.Marshal(e)
		s.written += len(b) + 1 // +1 for newline

		if s.written >= s.rotation.MaxSize {
			if err := s.rotate(); err != nil {
				return fmt.Errorf("audit jsonlog: rotate: %w", err)
			}
		}
	}

	return nil
}

// rotate closes the current file, shifts existing rotated files, and opens a new one.
func (s *JSONLogSink) rotate() error {
	if s.closer != nil {
		s.closer.Close()
		s.closer = nil
	}

	max := s.rotation.MaxFiles
	if max <= 0 {
		max = 5
	}

	// Remove the oldest rotated file.
	os.Remove(fmt.Sprintf("%s.%d", s.path, max))

	// Shift .{N} → .{N+1}, from highest to lowest to avoid overwrites.
	for i := max - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1))
	}

	// Current → .1
	os.Rename(s.path, s.path+".1")

	return s.openFile()
}

func (s *JSONLogSink) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}
