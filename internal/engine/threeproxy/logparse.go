package threeproxy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xoxproxy/xoxproxy/internal/engine"
)

// UsageRecord is one parsed engine log record: the per-connection
// traffic line emitted by the LogFormat defined in config.go. It is
// the raw material for the control plane's usage ledger and traffic
// monitoring (Phase 7); byte counts are integers end to end, never
// floating point.
type UsageRecord struct {
	UnixMillis      int64
	Service         string // e.g. "proxy"
	Port            int    // e.g. 3128
	ErrCode         int    // 0 = success; 10 = quota exceeded; 4x/5x = refused
	Username        string
	ClientIP        string
	ClientPort      int
	TargetIP        string // destination as requested: hostname when the client sent one, else resolved IP
	TargetPort      int
	BytesToTarget   int64 // %O: uploads (bytes sent to the target)
	BytesFromTarget int64 // %I: downloads (bytes received from the target)

	// RequestText is the trailing %T field (e.g. "CONNECT host:443" or
	// "GET http://host/ HTTP/1.1"). It classifies HTTP vs HTTPS CONNECT
	// traffic; it is never persisted — monitoring stores only metadata.
	RequestText string
}

// IsQuotaExceeded reports whether the connection was refused or cut by
// a traffic limit.
func (r UsageRecord) IsQuotaExceeded() bool { return r.ErrCode == 10 }

// ParseLogLine parses one line of the engine traffic log. Lines that do
// not match the expected record shape (3proxy also writes service
// lifecycle messages through the same log function) return an error;
// callers skip those. Parsing is defensive: log content is written by
// the engine from network input, so every field is validated and a
// malformed line can never misattribute traffic to a user.
func ParseLogLine(line string) (UsageRecord, error) {
	fields := strings.Fields(line)
	// ts, service.port, err, user, client:port, target:port, out, in,
	// hops — the trailing request text (%T) is ignored.
	const minFields = 9
	if len(fields) < minFields {
		return UsageRecord{}, fmt.Errorf("log line has %d fields, want >= %d", len(fields), minFields)
	}

	var rec UsageRecord

	ts, err := parseUnixMillis(fields[0])
	if err != nil {
		return UsageRecord{}, fmt.Errorf("timestamp: %w", err)
	}
	rec.UnixMillis = ts

	svc, port, err := parseService(fields[1])
	if err != nil {
		return UsageRecord{}, fmt.Errorf("service: %w", err)
	}
	rec.Service, rec.Port = svc, port

	errCode, err := parseInt(fields[2], "error code")
	if err != nil {
		return UsageRecord{}, err
	}
	rec.ErrCode = errCode

	if err := engine.ValidateUsername(fields[3]); err != nil {
		// The engine logs "-" for unauthenticated attempts; anything
		// else that fails the username policy cannot be attributed.
		if fields[3] != "-" {
			return UsageRecord{}, fmt.Errorf("username %q: %v", fields[3], err)
		}
	}
	rec.Username = fields[3]

	clientHost, clientPort, err := parseHostPort(fields[4])
	if err != nil {
		return UsageRecord{}, fmt.Errorf("client: %w", err)
	}
	rec.ClientIP, rec.ClientPort = clientHost, clientPort

	targetHost, targetPort, err := parseHostPort(fields[5])
	if err != nil {
		return UsageRecord{}, fmt.Errorf("target: %w", err)
	}
	rec.TargetIP, rec.TargetPort = targetHost, targetPort

	out, err := parseByteCount(fields[6], "bytes out")
	if err != nil {
		return UsageRecord{}, err
	}
	rec.BytesToTarget = out

	in, err := parseByteCount(fields[7], "bytes in")
	if err != nil {
		return UsageRecord{}, err
	}
	rec.BytesFromTarget = in

	if _, err := parseInt(fields[8], "hops"); err != nil {
		return UsageRecord{}, err
	}

	// The trailing request text (%T) is free-form; keep it verbatim for
	// protocol classification only.
	if len(fields) > 9 {
		rec.RequestText = strings.Join(fields[9:], " ")
	}

	return rec, nil
}

// parseUnixMillis handles the "%t.%." field: unix seconds.milliseconds.
func parseUnixMillis(s string) (int64, error) {
	dot := strings.IndexByte(s, '.')
	var secsStr, millisStr string
	if dot < 0 {
		secsStr = s
	} else {
		secsStr, millisStr = s[:dot], s[dot+1:]
	}
	secs, err := strconv.ParseInt(secsStr, 10, 64)
	if err != nil || secs < 0 {
		return 0, fmt.Errorf("timestamp %q is not unix time", s)
	}
	var millis int64
	if millisStr != "" {
		if len(millisStr) > 3 {
			millisStr = millisStr[:3]
		}
		if m, err := strconv.ParseInt(millisStr, 10, 64); err == nil {
			// "%." prints milliseconds without zero padding.
			for i := len(millisStr); i < 3; i++ {
				m *= 10
			}
			millis = m
		}
	}
	return secs*1000 + millis, nil
}

func parseService(s string) (string, int, error) {
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 || dot == len(s)-1 {
		return "", 0, fmt.Errorf("service field %q is not name.port", s)
	}
	port, err := strconv.Atoi(s[dot+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("service field %q has no valid port", s)
	}
	return s[:dot], port, nil
}

func parseHostPort(s string) (string, int, error) {
	// Bracketed IPv6: "[2001:db8::1]:443" — split after the closing
	// bracket, not at the first colon.
	var host, portStr string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return "", 0, fmt.Errorf("address %q has no port after the IPv6 bracket", s)
		}
		host, portStr = s[:end+1], s[end+2:]
	} else {
		var ok bool
		host, portStr, ok = strings.Cut(s, ":")
		if !ok {
			return "", 0, fmt.Errorf("address %q is not host:port", s)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("address %q has no valid port", s)
	}
	if host == "" || strings.ContainsAny(host, " \t\"'") {
		return "", 0, fmt.Errorf("address %q has no host", s)
	}
	return host, port, nil
}

func parseInt(s, what string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not numeric", what, s)
	}
	return v, nil
}

func parseByteCount(s, what string) (int64, error) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%s %q is not a byte count", what, s)
	}
	return v, nil
}
