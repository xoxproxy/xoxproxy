package analytics

import (
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

func recAt(ms int64, user, host string, bytesIn, bytesOut int64) Record {
	return Record{UnixMillis: ms, Username: user, Host: host, Port: 443,
		Protocol: store.StatHTTPS, BytesIn: bytesIn, BytesOut: bytesOut}
}

func dayStr(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02")
}

func TestAggregatorFoldsPerUserAndDay(t *testing.T) {
	a := NewAggregator(10, 0)
	a.Add(recAt(1000, "alice", "a.com", 100, 50))
	a.Add(recAt(2000, "alice", "a.com", 200, 60))
	a.Add(recAt(3000, "bob", "b.com", 10, 5))

	pending := a.TakePending()
	if len(pending) != 2 {
		t.Fatalf("pending users = %d, want 2", len(pending))
	}
	byUser := map[string]pendingDelta{}
	for _, p := range pending {
		byUser[p.Username] = p
	}
	alice := byUser["alice"]
	if len(alice.Usage) != 1 || alice.Usage[0].Day != dayStr(1000) {
		t.Fatalf("alice usage = %+v", alice.Usage)
	}
	u := alice.Usage[0]
	if u.BytesIn != 300 || u.BytesOut != 110 || u.Connections != 2 {
		t.Fatalf("alice counters = %+v", u)
	}
	if u.Month != u.Day[:7] {
		t.Fatalf("month %q must be day's YYYY-MM", u.Month)
	}
	// One destination, aggregated.
	if len(alice.Dests) != 1 || alice.Dests[0].Requests != 2 || alice.Dests[0].BytesIn != 300 {
		t.Fatalf("alice destinations = %+v", alice.Dests)
	}
	if alice.Usage[0].LastSeenUnix != 2000 {
		t.Fatalf("last seen = %d, want 2000", alice.Usage[0].LastSeenUnix)
	}

	// TakePending resets: a second take is empty.
	if pending := a.TakePending(); len(pending) != 0 {
		t.Fatalf("pending not reset: %+v", pending)
	}
}

func TestAggregatorSplitsDays(t *testing.T) {
	a := NewAggregator(10, 0)
	day1 := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC).UnixMilli()
	a.Add(recAt(day1, "alice", "a.com", 100, 0))
	a.Add(recAt(day2, "alice", "a.com", 300, 0))

	pending := a.TakePending()
	if len(pending) != 1 || len(pending[0].Usage) != 2 {
		t.Fatalf("usage rows = %+v, want two days", pending)
	}
	if len(pending[0].Dests) != 2 {
		t.Fatalf("destinations must be per-day: %+v", pending[0].Dests)
	}
}

func TestAggregatorUnauthenticatedNotPersisted(t *testing.T) {
	a := NewAggregator(10, 0)
	a.Add(recAt(1000, "-", "a.com", 100, 0))
	a.Add(recAt(1001, "", "a.com", 100, 0))

	if pending := a.TakePending(); len(pending) != 0 {
		t.Fatalf("unauthenticated traffic must not reach the ledger: %+v", pending)
	}
	// But it feeds the live view.
	snap := a.Snapshot()
	if snap.Requests != 2 || snap.BytesIn != 200 {
		t.Fatalf("live view = %+v", snap)
	}
}

func TestAggregatorDestinationCapOverflows(t *testing.T) {
	a := NewAggregator(2, 0)
	a.Add(recAt(1000, "alice", "a.com", 10, 0))
	a.Add(recAt(1001, "alice", "b.com", 10, 0))
	// Third distinct host overflows; the cap is per day.
	a.Add(recAt(1002, "alice", "c.com", 10, 0))
	a.Add(recAt(1003, "alice", "d.com", 10, 0))
	// Repeats of tracked hosts still land in their own buckets.
	a.Add(recAt(1004, "alice", "a.com", 5, 0))

	pending := a.TakePending()[0]
	found := map[string]int64{}
	for _, d := range pending.Dests {
		found[d.Host] = d.Requests
	}
	if found["a.com"] != 2 || found["b.com"] != 1 {
		t.Fatalf("tracked hosts = %v", found)
	}
	if found[OtherHost] != 2 {
		t.Fatalf("overflow bucket = %v", found)
	}
	if a.Snapshot().Overflowed != 2 {
		t.Fatalf("overflow counter = %d, want 2", a.Snapshot().Overflowed)
	}
	// Byte totals stay exact across tracked + overflow.
	var total int64
	for _, d := range pending.Dests {
		total += d.BytesIn
	}
	if total != 45 {
		t.Fatalf("total bytes = %d, want 45 (cap must not lose bytes)", total)
	}
}

func TestAggregatorSnapshotRollsDay(t *testing.T) {
	a := NewAggregator(10, 0)
	day1 := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC).UnixMilli()
	a.Add(recAt(day1, "alice", "a.com", 100, 0))
	if s := a.Snapshot(); s.Day != dayStr(day1) || s.BytesIn != 100 {
		t.Fatalf("day1 snapshot = %+v", s)
	}
	a.Add(recAt(day2, "alice", "a.com", 7, 0))
	if s := a.Snapshot(); s.Day != dayStr(day2) || s.BytesIn != 7 {
		t.Fatalf("day rollover must reset live totals: %+v", s)
	}
	// Flushes never reset the live view.
	a.TakePending()
	if s := a.Snapshot(); s.Requests != 2 && s.BytesIn != 7 {
		t.Fatalf("flush must not touch live totals: %+v", s)
	}
}

func TestAggregatorRing(t *testing.T) {
	a := NewAggregator(10, 3)
	a.Add(recAt(1000, "alice", "a.com", 0, 0))
	a.Add(recAt(2000, "bob", "b.com", 0, 0))
	a.Add(recAt(3000, "alice", "c.com", 0, 0))
	a.Add(recAt(4000, "bob", "d.com", 0, 0)) // evicts the 1000 record

	all := a.RecentConnections(10, "")
	if len(all) != 3 {
		t.Fatalf("ring size = %d, want 3", len(all))
	}
	// Newest first.
	want := []string{"d.com", "c.com", "b.com"}
	for i, rec := range all {
		if rec.Host != want[i] {
			t.Fatalf("order[%d] = %s, want %s (newest first)", i, rec.Host, want[i])
		}
	}

	// alice's oldest record (a.com) was evicted; only c.com remains.
	alice := a.RecentConnections(10, "alice")
	if len(alice) != 1 || alice[0].Host != "c.com" {
		t.Fatalf("alice filter = %+v", alice)
	}

	if got := a.RecentConnections(1, ""); len(got) != 1 || got[0].Host != "d.com" {
		t.Fatalf("limit = %+v", got)
	}
	if got := a.RecentConnections(0, ""); got != nil {
		t.Fatalf("limit 0 = %+v, want nil", got)
	}
}

func TestAggregatorRingDisabled(t *testing.T) {
	a := NewAggregator(10, 0)
	a.Add(recAt(1000, "alice", "a.com", 0, 0))
	if got := a.RecentConnections(10, ""); got != nil {
		t.Fatalf("disabled ring = %+v, want nil", got)
	}
	if a.Snapshot().RingEnabled {
		t.Fatal("RingEnabled must be false")
	}
}

func TestAggregatorBlockedCounter(t *testing.T) {
	a := NewAggregator(10, 0)
	r := recAt(1000, "alice", "a.com", 0, 0)
	r.Blocked = true
	a.Add(r)
	a.Add(recAt(1001, "alice", "a.com", 0, 0))

	pending := a.TakePending()[0]
	if pending.Dests[0].Blocked != 1 || pending.Dests[0].Requests != 2 {
		t.Fatalf("blocked/requests = %+v", pending.Dests[0])
	}
	if s := a.Snapshot(); s.Blocked != 1 {
		t.Fatalf("live blocked = %d, want 1", s.Blocked)
	}
}
