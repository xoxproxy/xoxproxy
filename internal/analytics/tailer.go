package analytics

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/engine/threeproxy"
	"github.com/xoxproxy/xoxproxy/internal/store"
)

// DefaultPollInterval is the traffic-log polling cadence. One second is
// far below the engine's log-write rate and costs one stat() call —
// inotify would add complexity (and a watch table) for no gain at this
// scale.
const DefaultPollInterval = time.Second

// Tailer follows the engine traffic log: it reads complete lines from a
// persisted cursor, detects rotation/truncation (file smaller than the
// cursor → restart at zero), and pushes parsed records to a callback. It
// never modifies the log and never blocks on the callback for long — the
// service hands records to a bounded queue.
type Tailer struct {
	path     string
	interval time.Duration
	logger   *slog.Logger

	mu     sync.Mutex
	offset int64
	// sawFile guards "log file appeared" logging so a missing engine
	// log does not spam once per second.
	sawFile bool

	malformed int64 // lines skipped (service lifecycle messages, corruption)
}

func NewTailer(path string, interval time.Duration, logger *slog.Logger, resume store.LogCursor) *Tailer {
	t := &Tailer{path: path, interval: interval, logger: logger}
	if resume.Path == path {
		t.offset = resume.Offset
	}
	return t
}

// Offset returns the byte position after the last line handed to the
// sink (the position that is safe to persist). Callers persist only an
// offset whose records have been aggregated; see Service.
func (t *Tailer) Offset() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offset
}

// Malformed returns how many lines were skipped since process start.
func (t *Tailer) Malformed() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.malformed
}

// Run polls until the context is cancelled. Each poll reads every
// complete line appended since the previous poll and calls sink with the
// records plus the offset after them. Errors are logged and retried on
// the next poll: a missing log (engine not started), a busy file, or a
// transient read error never stop the loop.
func (t *Tailer) Run(ctx context.Context, sink func(recs []Record, offsetAfter int64)) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.poll(sink)
		}
	}
}

// poll performs one read pass. The offset only ever advances past
// complete lines, so a half-written trailing line is re-read (and
// completed) on the next poll.
func (t *Tailer) poll(sink func([]Record, int64)) {
	info, err := os.Stat(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			t.logger.Warn("traffic log stat failed", slog.String("path", t.path), slog.String("error", err.Error()))
		}
		return
	}

	t.mu.Lock()
	offset := t.offset
	t.mu.Unlock()

	// Rotation or truncation: the file shrank below our position, so the
	// bytes after our cursor belong to a different generation. Restart
	// from zero; worst case (a same-size rotation) we lose or re-count a
	// few lines of accounting, never availability.
	if offset > 0 && info.Size() < offset {
		t.logger.Info("traffic log rotated or truncated; restarting from zero",
			slog.String("path", t.path),
			slog.Int64("old_offset", offset), slog.Int64("size", info.Size()))
		offset = 0
	}
	if !t.sawFile {
		t.sawFile = true
		t.logger.Info("tailing traffic log",
			slog.String("path", t.path), slog.Int64("resume_offset", offset))
	}

	f, err := os.Open(t.path)
	if err != nil {
		return // engine may hold it exclusively; retry next poll
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	var recs []Record
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 && line[len(line)-1] != '\n' {
			// Incomplete trailing line: leave it for the next poll.
			break
		}
		if len(line) > 0 {
			offset += int64(len(line))
			if parsed, perr := threeproxy.ParseLogLine(trimEOL(line)); perr == nil {
				recs = append(recs, FromUsage(parsed))
			} else {
				t.mu.Lock()
				t.malformed++
				t.mu.Unlock()
			}
		}
		if err != nil {
			break // EOF (or read error — the next poll re-reads from offset)
		}
	}

	t.mu.Lock()
	t.offset = offset
	t.mu.Unlock()

	if len(recs) > 0 {
		sink(recs, offset)
	}
}

func trimEOL(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	return s
}
