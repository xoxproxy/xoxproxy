package threeproxy

import (
	"strings"
	"testing"
)

// Sample lines follow the logformat defined in config.go:
// G%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T
func TestParseLogLineValid(t *testing.T) {
	rec, err := ParseLogLine("1760380800.123 proxy.3128 0 alice 203.0.113.7:52222 93.184.216.34:443 1049 95128 0 GET http://example.com/ HTTP/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UnixMillis != 1760380800123 {
		t.Errorf("UnixMillis = %d, want 1760380800123", rec.UnixMillis)
	}
	if rec.Service != "proxy" || rec.Port != 3128 {
		t.Errorf("service = %s.%d", rec.Service, rec.Port)
	}
	if rec.ErrCode != 0 {
		t.Errorf("err code = %d", rec.ErrCode)
	}
	if rec.Username != "alice" {
		t.Errorf("username = %q", rec.Username)
	}
	if rec.ClientIP != "203.0.113.7" || rec.ClientPort != 52222 {
		t.Errorf("client = %s:%d", rec.ClientIP, rec.ClientPort)
	}
	if rec.TargetIP != "93.184.216.34" || rec.TargetPort != 443 {
		t.Errorf("target = %s:%d", rec.TargetIP, rec.TargetPort)
	}
	if rec.BytesToTarget != 1049 {
		t.Errorf("bytes to target = %d", rec.BytesToTarget)
	}
	if rec.BytesFromTarget != 95128 {
		t.Errorf("bytes from target = %d", rec.BytesFromTarget)
	}
	if rec.IsQuotaExceeded() {
		t.Error("success record flagged as quota-exceeded")
	}
}

func TestParseLogLineVariants(t *testing.T) {
	// SOCKS record, failed auth ("-"), no millis, no request text.
	rec, err := ParseLogLine("1760380800 socks.1080 4 - 198.51.100.9:40000 0.0.0.0:0 0 0 0")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UnixMillis != 1760380800000 {
		t.Errorf("UnixMillis = %d", rec.UnixMillis)
	}
	if rec.Username != "-" || rec.ErrCode != 4 {
		t.Errorf("unexpected record: %+v", rec)
	}

	// Quota-exceeded record.
	rec, err = ParseLogLine("1760380800.5 proxy.3128 10 bob 203.0.113.7:52222 93.184.216.34:443 500 10485760 0 CONNECT example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.IsQuotaExceeded() {
		t.Error("error 10 not reported as quota exceeded")
	}
	if rec.BytesFromTarget != 10485760 {
		t.Errorf("download bytes = %d", rec.BytesFromTarget)
	}

	// IPv6 client (bracketed by the engine).
	rec, err = ParseLogLine("1760380800.1 proxy.3128 0 dave [2001:db8::1]:52222 [2001:db8::2]:443 10 20 0 GET http://x/")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ClientIP != "[2001:db8::1]" {
		t.Errorf("ipv6 client = %q", rec.ClientIP)
	}

	// Milliseconds without zero padding: ".5" = 500ms.
	rec, err = ParseLogLine("1760380800.5 proxy.3128 0 dave 1.2.3.4:1 5.6.7.8:2 0 0 0")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UnixMillis != 1760380800500 {
		t.Errorf("UnixMillis = %d, want ...500", rec.UnixMillis)
	}
}

func TestParseLogLineRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"garbage",
		"1760380800.123 proxy 0 alice 1.2.3.4:1 5.6.7.8:2 10 20 0",    // service without port
		"1760380800.123 proxy.3128 0 alice 1.2.3.4 5.6.7.8:2 10 20 0", // client without port
		"1760380800.123 proxy.3128 0 alice 1.2.3.4:1 5.6.7.8:2 ten 20 0",
		"1760380800.123 proxy.3128 0 alice 1.2.3.4:1 5.6.7.8:2 -10 20 0", // negative bytes
		"1760380800.123 proxy.3128 zero alice 1.2.3.4:1 5.6.7.8:2 10 20 0",
		"notatime.123 proxy.3128 0 alice 1.2.3.4:1 5.6.7.8:2 10 20 0",
		"1760380800.123 proxy.3128 0 alice 1.2.3.4:1 5.6.7.8:2 10 20",
		"1760380800.123 proxy.3128 0 ' OR 1=1 1.2.3.4:1 5.6.7.8:2 10 20 0",
	}
	for _, line := range bad {
		if _, err := ParseLogLine(line); err == nil {
			t.Errorf("parsed malformed line %q", line)
		}
	}
}

// TestSecurityLogInjectionNoMisattribution: hostile strings in log
// lines must never parse into a record attributed to a real user. The
// username field is validated with the same policy the engine config
// uses, so injected whitespace/quotes make the line unparseable rather
// than shifting fields.
func TestSecurityLogInjectionNoMisattribution(t *testing.T) {
	hostile := []string{
		"1760380800.123 proxy.3128 0 bob alice 1.2.3.4:1 5.6.7.8:2 10 20 0", // extra field shifts everything
		"1760380800.123 proxy.3128 0 ' OR '1'='1 1.2.3.4:1 5.6.7.8:2 10 20 0",
		"1760380800.123 proxy.3128 0 bob\nallow * 1.2.3.4:1 5.6.7.8:2 10 20 0",
		"1760380800.123 proxy.3128 0 alice:CL:x 1.2.3.4:1 5.6.7.8:2 10 20 0",
	}
	for _, line := range hostile {
		rec, err := ParseLogLine(line)
		if err == nil && rec.Username == "alice" {
			t.Errorf("hostile line attributed traffic to alice: %q -> %+v", line, rec)
		}
	}
	// Control: a well-formed bob line still parses and attributes to bob.
	rec, err := ParseLogLine("1760380800.123 proxy.3128 0 bob 1.2.3.4:1 5.6.7.8:2 10 20 0")
	if err != nil || rec.Username != "bob" {
		t.Fatalf("control line failed: %+v %v", rec, err)
	}
	// A username field with a space cannot split into a valid record at all.
	if _, err := ParseLogLine("1760380800.123 proxy.3128 0 al ice 1.2.3.4:1 5.6.7.8:2 10 20 0"); err == nil {
		t.Error("space-containing username field parsed")
	}
	_ = strings.TrimSpace // keep strings import if unused elsewhere
}
