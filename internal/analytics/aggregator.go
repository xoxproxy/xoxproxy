package analytics

import (
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// OtherHost is the overflow bucket for destinations beyond a user's cap.
// Overflow keeps per-protocol and per-port attribution while bounding the
// number of distinct rows a user can generate per day.
const OtherHost = "(other)"

// destKey identifies one aggregated destination of one user.
type destKey struct {
	Host     string
	Port     int
	Protocol string
}

// counters accumulates bytes/request counters between flushes.
type counters struct {
	Requests int64
	Blocked  int64
	BytesIn  int64
	BytesOut int64
}

func (c *counters) add(r Record) {
	c.Requests++
	if r.Blocked {
		c.Blocked++
	}
	c.BytesIn += r.BytesIn
	c.BytesOut += r.BytesOut
}

// dayAgg is one user's pending contribution for one UTC day: the whole-day
// usage counters plus per-destination counters. Destination cardinality is
// capped per day, so the database holds at most maxDestinations (+ a few
// overflow) rows per user per day — the bound operators configure.
type dayAgg struct {
	usage   counters
	dests   map[destKey]*counters
	tracked int // distinct non-overflow destinations; the cap applies here
}

// userAgg is everything one user contributes between flushes.
type userAgg struct {
	Days         map[string]*dayAgg // day (YYYY-MM-DD) → counters
	LastSeenUnix int64
}

func newUserAgg() *userAgg {
	return &userAgg{Days: map[string]*dayAgg{}}
}

func (u *userAgg) day(day string) *dayAgg {
	d := u.Days[day]
	if d == nil {
		d = &dayAgg{dests: map[destKey]*counters{}}
		u.Days[day] = d
	}
	return d
}

// todayTotals is the in-memory live view for one day. Unlike the pending
// counters it is never reset by a flush; it rolls over when the UTC day
// changes.
type todayTotals struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
	Blocked  int64
}

// Aggregator is the bounded in-memory stage of the pipeline: it folds
// records into per-user, per-day counters (destination cardinality capped)
// and an optional fixed-size recent-connections ring. TakePending swaps
// the counters out atomically; aggregation continues into fresh ones, so
// a slow database flush never blocks ingestion.
type Aggregator struct {
	mu         sync.Mutex
	maxDests   int
	ring       *ring
	users      map[string]*userAgg
	today      map[string]*todayTotals // keyed by day; only the newest is kept
	todayDay   string
	ingested   int64
	overflowed int64 // records folded into "(other)" buckets
}

func NewAggregator(maxDestinationsPerUser, ringSize int) *Aggregator {
	a := &Aggregator{
		maxDests: maxDestinationsPerUser,
		users:    map[string]*userAgg{},
		today:    map[string]*todayTotals{},
	}
	if ringSize > 0 {
		a.ring = newRing(ringSize)
	}
	return a
}

// Add folds one record into the pending counters. Unauthenticated
// attempts ("-") cannot be attributed to a user: they still feed the ring
// and the live totals, but never the persisted per-user stats.
func (a *Aggregator) Add(rec Record) {
	day := time.UnixMilli(rec.UnixMillis).UTC().Format("2006-01-02")

	a.mu.Lock()
	defer a.mu.Unlock()

	a.ingested++
	a.addToday(day, rec)
	if a.ring != nil {
		a.ring.add(rec)
	}
	if rec.Username == "-" || rec.Username == "" {
		return
	}

	u := a.users[rec.Username]
	if u == nil {
		u = newUserAgg()
		a.users[rec.Username] = u
	}
	if rec.UnixMillis > u.LastSeenUnix {
		u.LastSeenUnix = rec.UnixMillis
	}

	d := u.day(day)
	d.usage.add(rec)

	key := destKey{Host: rec.Host, Port: rec.Port, Protocol: rec.Protocol}
	if c := d.dests[key]; c != nil {
		c.add(rec)
		return
	}
	if d.tracked < a.maxDests {
		d.tracked++
		d.dests[key] = &counters{}
		d.dests[key].add(rec)
		return
	}
	// Over the cap: fold into the "(other)" bucket for this port+protocol
	// so the row count stays bounded while the byte totals stay exact.
	oKey := destKey{Host: OtherHost, Port: rec.Port, Protocol: rec.Protocol}
	if d.dests[oKey] == nil {
		d.dests[oKey] = &counters{}
	}
	d.dests[oKey].add(rec)
	a.overflowed++
}

// addToday maintains the live view. day is the record's UTC day.
func (a *Aggregator) addToday(day string, rec Record) {
	if day != a.todayDay {
		delete(a.today, a.todayDay)
		a.todayDay = day
	}
	t := a.today[day]
	if t == nil {
		t = &todayTotals{}
		a.today[day] = t
	}
	t.BytesIn += rec.BytesIn
	t.BytesOut += rec.BytesOut
	t.Requests++
	if rec.Blocked {
		t.Blocked++
	}
}

// pendingDelta is one user's flush contribution before the username is
// resolved to a user id.
type pendingDelta struct {
	Username string
	Usage    []store.UsageDelta
	Dests    []store.DestinationDelta
	Records  int64
}

// TakePending swaps out everything accumulated since the last flush. The
// returned deltas carry UserID zero; the caller resolves usernames (an
// unknown user's pending traffic is dropped, never misattributed to
// another account).
func (a *Aggregator) TakePending() []pendingDelta {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]pendingDelta, 0, len(a.users))
	for name, u := range a.users {
		p := pendingDelta{Username: name}
		for day, d := range u.Days {
			p.Usage = append(p.Usage, store.UsageDelta{
				Username:     name,
				Day:          day,
				Month:        day[:7],
				BytesIn:      d.usage.BytesIn,
				BytesOut:     d.usage.BytesOut,
				Connections:  d.usage.Requests,
				LastSeenUnix: u.LastSeenUnix,
			})
			p.Records += d.usage.Requests
			lastSeen := time.UnixMilli(u.LastSeenUnix).UTC()
			for k, c := range d.dests {
				p.Dests = append(p.Dests, store.DestinationDelta{
					UserID:   0, // resolved by the service
					Day:      day,
					Host:     k.Host,
					Port:     k.Port,
					Protocol: k.Protocol,
					Requests: c.Requests,
					Blocked:  c.Blocked,
					BytesIn:  c.BytesIn,
					BytesOut: c.BytesOut,
					LastSeen: lastSeen,
				})
			}
		}
		out = append(out, p)
		delete(a.users, name)
	}
	return out
}

// LiveSnapshot is the in-memory view of the current day plus pipeline
// health counters. It answers the dashboard's "live" panel without
// touching the database.
type LiveSnapshot struct {
	Day        string `json:"day"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	Requests   int64  `json:"requests"`
	Blocked    int64  `json:"blocked"`
	Ingested   int64  `json:"ingested"`   // records folded since process start
	Overflowed int64  `json:"overflowed"` // records folded into "(other)" buckets
	Dropped    int64  `json:"dropped"`    // records dropped by a full queue (set by the service)
	// LogOffset and MalformedLines are the tailer's view, filled in by the
	// service (the aggregator does not see them).
	LogOffset      int64 `json:"log_offset"`
	MalformedLines int64 `json:"malformed_lines"`
	RingEnabled    bool  `json:"ring_enabled"`
}

// Snapshot returns the live view of the aggregator.
func (a *Aggregator) Snapshot() LiveSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := LiveSnapshot{
		Day:         a.todayDay,
		Ingested:    a.ingested,
		Overflowed:  a.overflowed,
		RingEnabled: a.ring != nil,
	}
	if t := a.today[a.todayDay]; t != nil {
		s.BytesIn, s.BytesOut, s.Requests, s.Blocked = t.BytesIn, t.BytesOut, t.Requests, t.Blocked
	}
	return s
}

// RecentConnections returns up to limit newest records, optionally
// filtered by username. limit <= 0 yields an empty slice.
func (a *Aggregator) RecentConnections(limit int, username string) []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ring == nil || limit <= 0 {
		return nil
	}
	return a.ring.recent(limit, username)
}

// --- ring ---

// ring is a fixed-size circular buffer of the most recent records. It is
// never persisted: it exists so the dashboard's live view has bounded
// cost regardless of traffic volume.
type ring struct {
	buf  []Record
	next int // slot the next record lands in; the oldest once full
	size int
}

func newRing(capacity int) *ring {
	return &ring{buf: make([]Record, capacity)}
}

func (r *ring) add(rec Record) {
	r.buf[r.next] = rec
	r.next = (r.next + 1) % len(r.buf)
	if r.size < len(r.buf) {
		r.size++
	}
}

// recent walks from the newest record backwards, newest first.
func (r *ring) recent(limit int, username string) []Record {
	n := r.size
	if limit < n {
		n = limit
	}
	out := make([]Record, 0, n)
	for i := 0; i < r.size && len(out) < n; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		rec := r.buf[idx]
		if username != "" && rec.Username != username {
			continue
		}
		out = append(out, rec)
	}
	return out
}
