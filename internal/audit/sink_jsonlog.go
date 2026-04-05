package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// JSONLogSink writes one JSON line per event to an io.Writer.
// "stdout" writes to os.Stdout; anything else is treated as a file path.
type JSONLogSink struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer // nil when writing to stdout
	enc    *json.Encoder
}

// NewJSONLogSink creates a sink that writes JSON lines to dest.
// dest is "stdout" for os.Stdout, or a file path (parent dirs are created).
func NewJSONLogSink(dest string) (*JSONLogSink, error) {
	var w io.Writer
	var closer io.Closer

	if dest == "stdout" {
		w = os.Stdout
	} else {
		if err := os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
			return nil, fmt.Errorf("audit jsonlog: mkdir %s: %w", filepath.Dir(dest), err)
		}
		f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("audit jsonlog: open %s: %w", dest, err)
		}
		w = f
		closer = f
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	return &JSONLogSink{w: w, closer: closer, enc: enc}, nil
}

func (s *JSONLogSink) Name() string { return "jsonlog" }

func (s *JSONLogSink) Emit(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(e)
}

func (s *JSONLogSink) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}
