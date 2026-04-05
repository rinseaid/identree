package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogSink sends RFC 5424 syslog messages over UDP or TCP.
// URL format: "udp://host:port" or "tcp://host:port".
type SyslogSink struct {
	mu       sync.Mutex
	network  string // "udp" or "tcp"
	addr     string
	conn     net.Conn
	hostname string
}

// NewSyslogSink creates a syslog sink. url is "udp://host:514" or "tcp://host:601".
func NewSyslogSink(url string) (*SyslogSink, error) {
	network, addr, err := parseSyslogURL(url)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "identree"
	}
	s := &SyslogSink{
		network:  network,
		addr:     addr,
		hostname: hostname,
	}
	// Attempt initial connection but don't fail — reconnect on first Emit.
	s.conn, _ = net.DialTimeout(network, addr, 5*time.Second)
	return s, nil
}

func (s *SyslogSink) Name() string { return "syslog" }

// Emit formats and sends a single RFC 5424 syslog message.
// Facility 10 (authpriv), severity 6 (info) = priority 86.
func (s *SyslogSink) Emit(e Event) error {
	msg, err := formatRFC5424(e, s.hostname)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Lazy reconnect.
	if s.conn == nil {
		s.conn, err = net.DialTimeout(s.network, s.addr, 5*time.Second)
		if err != nil {
			return fmt.Errorf("syslog connect: %w", err)
		}
	}

	_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = s.conn.Write(msg)
	if err != nil {
		// Drop the broken connection so next Emit reconnects.
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// formatRFC5424 produces: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
func formatRFC5424(e Event, hostname string) ([]byte, error) {
	// Facility=10 (authpriv) × 8 + Severity=6 (info) = 86
	const pri = 86

	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}

	// Structured data: [identree@0 event="..." username="..."]
	sd := fmt.Sprintf(`[identree@0 event="%s" username="%s" hostname="%s"]`,
		syslogEscape(e.Event), syslogEscape(e.Username), syslogEscape(e.Hostname))

	// RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	ts := e.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	line := fmt.Sprintf("<%d>1 %s %s identree - - %s %s\n",
		pri, ts, hostname, sd, data)

	return []byte(line), nil
}

// syslogEscape escapes characters that are not safe in RFC 5424 SD-PARAM values.
func syslogEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

func parseSyslogURL(url string) (network, addr string, err error) {
	switch {
	case strings.HasPrefix(url, "udp://"):
		return "udp", strings.TrimPrefix(url, "udp://"), nil
	case strings.HasPrefix(url, "tcp://"):
		return "tcp", strings.TrimPrefix(url, "tcp://"), nil
	default:
		return "", "", fmt.Errorf("audit syslog: URL must start with udp:// or tcp:// (got %q)", url)
	}
}
