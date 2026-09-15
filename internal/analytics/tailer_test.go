package analytics

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// logLine builds one engine traffic-log line in the format ParseLogLine
// expects: ts service.port err user client:port target:port out in hops
// request-text.
func logLine(ts int64, user, target string, port int, blocked bool) string {
	errCode := 0
	if blocked {
		errCode = 10
	}
	return itoa(ts) + " proxy.3128 " + strconv.Itoa(errCode) + " " + user +
		" 10.0.0.1:40000 " + target + ":" + strconv.Itoa(port) + " 100 900 0 GET http://" + target + "/ HTTP/1.1\n"
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pollOnce runs a single tailer poll and returns the records it produced.
func pollOnce(t *testing.T, tailer *Tailer) []Record {
	t.Helper()
	var recs []Record
	tailer.poll(func(r []Record, _ int64) { recs = append(recs, r...) })
	return recs
}

func TestTailerReadsAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.log")
	if err := os.WriteFile(path, []byte(logLine(1000, "alice", "a.com", 80, false)), 0o640); err != nil {
		t.Fatal(err)
	}
	tailer := NewTailer(path, time.Second, testLogger(), store.LogCursor{})

	recs := pollOnce(t, tailer)
	if len(recs) != 1 || recs[0].Username != "alice" || recs[0].Host != "a.com" {
		t.Fatalf("first poll = %+v", recs)
	}
	offset := tailer.Offset()
	if offset == 0 {
		t.Fatal("offset must advance past the line")
	}

	// Nothing new: no records, offset unchanged.
	if recs := pollOnce(t, tailer); len(recs) != 0 {
		t.Fatalf("re-poll re-read old lines: %+v", recs)
	}
	if tailer.Offset() != offset {
		t.Fatal("offset changed without new data")
	}

	// Append two lines: exactly those are returned.
	more := logLine(2000, "bob", "b.com", 443, true) + logLine(3000, "alice", "c.com", 80, false)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(more); err != nil {
		t.Fatal(err)
	}
	f.Close()

	recs = pollOnce(t, tailer)
	if len(recs) != 2 || recs[0].Username != "bob" || recs[1].Username != "alice" {
		t.Fatalf("second poll = %+v", recs)
	}
	if !recs[0].Blocked || recs[0].Port != 443 {
		t.Fatalf("field mapping off: %+v", recs[0])
	}
}

func TestTailerIncompleteTrailingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.log")
	full := logLine(1000, "alice", "a.com", 80, false)
	// A half-written trailing line must not be consumed (no trailing \n).
	if err := os.WriteFile(path, []byte(full+"1700000000 proxy.31"), 0o640); err != nil {
		t.Fatal(err)
	}
	tailer := NewTailer(path, time.Second, testLogger(), store.LogCursor{})

	recs := pollOnce(t, tailer)
	if len(recs) != 1 {
		t.Fatalf("complete line not parsed: %+v", recs)
	}
	offset := tailer.Offset()
	if offset != int64(len(full)) {
		t.Fatalf("offset = %d, want %d (must stop at the newline)", offset, len(full))
	}

	// Complete the line; it is read on the next poll.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	f.WriteString("28 0 alice 10.0.0.1:1 d.com:80 1 1 0 GET http://d.com/\n")
	f.Close()
	if recs := pollOnce(t, tailer); len(recs) != 1 || recs[0].Host != "d.com" {
		t.Fatalf("completed line not parsed: %+v", recs)
	}
}

func TestTailerRotationRestartsFromZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.log")
	if err := os.WriteFile(path, []byte(logLine(1000, "alice", "a.com", 80, false)+
		logLine(2000, "bob", "b.com", 80, false)), 0o640); err != nil {
		t.Fatal(err)
	}
	tailer := NewTailer(path, time.Second, testLogger(), store.LogCursor{})
	pollOnce(t, tailer)
	offset := tailer.Offset()
	if offset == 0 {
		t.Fatal("precondition: offset advanced")
	}

	// Simulate rotation: the file is replaced by a fresh, smaller one.
	if err := os.WriteFile(path, []byte(logLine(3000, "carol", "c.com", 80, false)), 0o640); err != nil {
		t.Fatal(err)
	}
	recs := pollOnce(t, tailer)
	if len(recs) != 1 || recs[0].Username != "carol" {
		t.Fatalf("after rotation = %+v, want the fresh file's line", recs)
	}
	if tailer.Offset() > offset {
		t.Fatal("offset must have restarted from zero for the smaller file")
	}
}

func TestTailerResumeCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.log")
	lines := logLine(1000, "alice", "a.com", 80, false) + logLine(2000, "bob", "b.com", 80, false)
	if err := os.WriteFile(path, []byte(lines), 0o640); err != nil {
		t.Fatal(err)
	}

	// Resume past line 1: only line 2 is read.
	firstLen := int64(len(logLine(1000, "alice", "a.com", 80, false)))
	tailer := NewTailer(path, time.Second, testLogger(), store.LogCursor{Path: path, Offset: firstLen})
	recs := pollOnce(t, tailer)
	if len(recs) != 1 || recs[0].Username != "bob" {
		t.Fatalf("resumed poll = %+v", recs)
	}
	if tailer.Offset() != int64(len(lines)) {
		t.Fatal("resume must end at EOF")
	}

	// A cursor for a different path is ignored (log moved).
	other := NewTailer(path, time.Second, testLogger(), store.LogCursor{Path: "/elsewhere", Offset: firstLen})
	if recs := pollOnce(t, other); len(recs) != 2 {
		t.Fatalf("foreign cursor must not skip data: %+v", recs)
	}
}

func TestTailerMalformedLinesSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.log")
	// Service lifecycle noise the engine writes through the same log.
	content := "1700000000 [3proxy] service started\n" +
		logLine(1000, "alice", "a.com", 80, false) +
		"garbage line\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	tailer := NewTailer(path, time.Second, testLogger(), store.LogCursor{})

	recs := pollOnce(t, tailer)
	if len(recs) != 1 || recs[0].Username != "alice" {
		t.Fatalf("valid lines = %+v", recs)
	}
	if got := tailer.Malformed(); got != 2 {
		t.Fatalf("malformed = %d, want 2", got)
	}
}

func TestTailerMissingFileIsQuiet(t *testing.T) {
	tailer := NewTailer(filepath.Join(t.TempDir(), "absent.log"), time.Second, testLogger(), store.LogCursor{})
	if recs := pollOnce(t, tailer); recs != nil {
		t.Fatalf("missing log must yield nothing: %+v", recs)
	}
	if tailer.Malformed() != 0 {
		t.Fatal("missing file is not a malformed line")
	}
}
