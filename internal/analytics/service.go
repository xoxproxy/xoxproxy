package analytics

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// finalFlushTimeout bounds the best-effort flush at shutdown. Unflushed
// records are not lost: the persisted cursor still points before them, so
// the next start re-reads and counts them.
const finalFlushTimeout = 5 * time.Second

// pruneInterval is the destination-retention cadence. Pruning is a cheap
// indexed DELETE; an hour between runs bounds staleness far below any
// retention window an operator would set.
const pruneInterval = time.Hour

// Options configures the pipeline. The zero value is not usable — callers
// derive every field from a validated config.AnalyticsConfig.
type Options struct {
	// LogPath is the engine traffic log to tail.
	LogPath string
	// FlushInterval is the counter-flush cadence.
	FlushInterval time.Duration
	// QueueSize bounds the ingestion queue (records). When full, records
	// are dropped and counted, never buffered unboundedly.
	QueueSize int
	// RingSize is the recent-connections ring size; 0 disables the ring
	// (verbosity "counters").
	RingSize int
	// MaxDestinationsPerUser caps tracked destinations per user per day.
	MaxDestinationsPerUser int
	// RetentionDays prunes per-destination stats older than this many
	// days; 0 keeps them forever. Usage ledgers are never pruned.
	RetentionDays int
	// PollInterval overrides the traffic-log poll cadence (tests); 0 uses
	// DefaultPollInterval.
	PollInterval time.Duration
}

// Service is the analytics pipeline: tailer → bounded queue → aggregator →
// batched flush. Start runs it until the context is cancelled; everything
// before Start is pure setup. Query methods are safe to call from any
// goroutine at any time.
type Service struct {
	logger *slog.Logger
	repo   store.AnalyticsRepository
	users  store.UserRepository
	opts   Options

	tailer *Tailer
	agg    *Aggregator

	// q carries records from the tailer (producer, once per poll) to the
	// service loop (consumer). Bounded: a full queue drops, it never
	// blocks the tailer.
	q chan Record

	dropped atomic.Int64

	// retry holds a flush batch whose ApplyDeltas failed, to be merged
	// into the next flush. Guarded by the service loop (only the loop
	// goroutine touches it).
	retry []pendingDelta

	// lastPersisted is the offset of the last successfully flushed batch;
	// only used to skip no-op flushes.
	lastPersisted int64

	done chan struct{}
}

// NewService builds the pipeline. resume is the persisted traffic-log
// cursor (zero value to start from the beginning); the caller loads it so
// this constructor does no I/O.
func NewService(logger *slog.Logger, repo store.AnalyticsRepository, users store.UserRepository, resume store.LogCursor, opts Options) *Service {
	interval := opts.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	ring := opts.RingSize
	if ring < 0 {
		ring = 0
	}
	s := &Service{
		logger: logger,
		repo:   repo,
		users:  users,
		opts:   opts,
		tailer: NewTailer(opts.LogPath, interval, logger, resume),
		agg:    NewAggregator(opts.MaxDestinationsPerUser, ring),
		q:      make(chan Record, opts.QueueSize),
		done:   make(chan struct{}),
	}
	return s
}

// Start runs the pipeline until ctx is cancelled, then performs one
// best-effort final flush. It blocks; run it in a goroutine and use Done
// to wait for the final flush to complete.
func (s *Service) Start(ctx context.Context) {
	defer close(s.done)

	go s.tailer.Run(ctx, s.enqueue)

	flushTicker := time.NewTicker(s.opts.FlushInterval)
	defer flushTicker.Stop()
	pruneTicker := time.NewTicker(pruneInterval)
	defer pruneTicker.Stop()

	// Retention runs once at start (a long-stopped server may have old
	// rows) and then on its own cadence.
	s.prune(ctx)

	for {
		select {
		case rec := <-s.q:
			s.agg.Add(rec)
		case <-flushTicker.C:
			s.flush(ctx)
		case <-pruneTicker.C:
			s.prune(ctx)
		case <-ctx.Done():
			// The parent context is cancelled; the final flush gets its
			// own deadline so shutdown cannot hang on a stuck write.
			fctx, cancel := context.WithTimeout(context.Background(), finalFlushTimeout)
			s.flush(fctx)
			cancel()
			return
		}
	}
}

// Done is closed when Start has finished, including the final flush.
func (s *Service) Done() <-chan struct{} { return s.done }

// enqueue is the tailer sink: hand every record to the bounded queue,
// dropping (and counting) when it is full. Dropping is the deliberate
// overload behavior — the alternative, blocking the tailer, would let the
// engine log grow unread and eventually lose far more.
func (s *Service) enqueue(recs []Record, offsetAfter int64) {
	for _, rec := range recs {
		select {
		case s.q <- rec:
		default:
			s.dropped.Add(1)
		}
	}
}

// flush drains the queue, folds everything into the aggregator, resolves
// usernames to user ids, and persists the batch plus the log cursor in one
// transaction. A failed batch is kept and merged into the next flush.
func (s *Service) flush(ctx context.Context) {
	// Drain everything queued so far; the tailer appends at most one batch
	// per poll, and the queue is empty again long before the next tick.
drain:
	for {
		select {
		case rec := <-s.q:
			s.agg.Add(rec)
		default:
			break drain
		}
	}

	pending := s.agg.TakePending()
	if len(s.retry) > 0 {
		pending = append(s.retry, pending...)
		s.retry = nil
	}

	offset := s.tailer.Offset()
	if len(pending) == 0 && offset == s.lastPersisted {
		return
	}

	usage, dests, err := s.resolve(ctx, pending)
	if err != nil {
		// A lookup error (database down) aborts the whole flush; the batch
		// is retried next tick. Only a confirmed unknown user drops data.
		s.retry = pending
		s.logger.Warn("analytics flush deferred; user lookup failed",
			slog.String("error", err.Error()))
		return
	}

	cursor := store.LogCursor{Path: s.opts.LogPath, Offset: offset}
	if err := s.repo.ApplyDeltas(ctx, usage, dests, cursor); err != nil {
		s.retry = pending
		s.logger.Warn("analytics flush failed; will retry",
			slog.String("error", err.Error()))
		return
	}
	s.lastPersisted = offset

	if len(usage) > 0 {
		s.logger.Debug("analytics flushed",
			slog.Int("users", len(usage)), slog.Int("destinations", len(dests)),
			slog.Int64("offset", offset))
	}
}

// resolve maps each pending delta's username to a user id. A username the
// store does not know (deleted after the traffic happened) drops that
// user's batch — traffic is never attributed to the wrong account. Any
// other lookup error fails the flush so the batch is retried whole.
func (s *Service) resolve(ctx context.Context, pending []pendingDelta) ([]store.UsageDelta, []store.DestinationDelta, error) {
	ids := make(map[string]int64, len(pending))
	var usage []store.UsageDelta
	var dests []store.DestinationDelta
	var unknown []string

	for _, p := range pending {
		id, ok := ids[p.Username]
		if !ok {
			u, err := s.users.GetUserByUsername(ctx, p.Username)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					ids[p.Username] = 0
					unknown = append(unknown, p.Username)
					continue
				}
				return nil, nil, err
			}
			id = u.ID
			ids[p.Username] = id
		}
		if id == 0 {
			continue
		}
		for i := range p.Usage {
			p.Usage[i].UserID = id
			usage = append(usage, p.Usage[i])
		}
		for i := range p.Dests {
			p.Dests[i].UserID = id
			dests = append(dests, p.Dests[i])
		}
	}
	if len(unknown) > 0 {
		s.logger.Debug("analytics dropped traffic of unknown users",
			slog.Any("usernames", unknown))
	}
	return usage, dests, nil
}

// prune enforces the destination-stat retention window. Usage ledgers are
// the quota ledger and are never pruned.
func (s *Service) prune(ctx context.Context) {
	if s.opts.RetentionDays <= 0 {
		return
	}
	before := time.Now().UTC().AddDate(0, 0, -s.opts.RetentionDays).Format("2006-01-02")
	n, err := s.repo.PruneDestinations(ctx, before)
	if err != nil {
		s.logger.Warn("destination retention prune failed",
			slog.String("error", err.Error()))
		return
	}
	if n > 0 {
		s.logger.Info("pruned destination stats",
			slog.String("before", before), slog.Int64("rows", n))
	}
}

// --- read-side API (dashboard queries) ---

// Live returns the current-day counters plus pipeline health.
func (s *Service) Live() LiveSnapshot {
	snap := s.agg.Snapshot()
	snap.Dropped = s.dropped.Load()
	snap.LogOffset = s.tailer.Offset()
	snap.MalformedLines = s.tailer.Malformed()
	return snap
}

// RecentConnections returns the newest records from the live ring, newest
// first, optionally filtered by username. Empty when the ring is disabled.
func (s *Service) RecentConnections(limit int, username string) []Record {
	return s.agg.RecentConnections(limit, username)
}

// GlobalTraffic returns day-granularity usage summed across all users.
func (s *Service) GlobalTraffic(ctx context.Context, since time.Time) ([]store.UsagePeriod, error) {
	return s.repo.ListGlobalTraffic(ctx, since)
}

// UserTraffic returns a user's day-granularity usage.
func (s *Service) UserTraffic(ctx context.Context, userID int64, since time.Time) ([]store.UsagePeriod, error) {
	return s.repo.ListUserTraffic(ctx, userID, since)
}

// UserDestinations returns a user's destination stats since sinceDay.
func (s *Service) UserDestinations(ctx context.Context, userID int64, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.repo.ListUserDestinations(ctx, userID, sinceDay, limit)
}

// TopDestinations returns the global top destinations since sinceDay.
func (s *Service) TopDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.repo.ListTopDestinations(ctx, sinceDay, limit)
}

// BlockedDestinations returns destinations with blocked requests since
// sinceDay.
func (s *Service) BlockedDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.repo.ListBlockedDestinations(ctx, sinceDay, limit)
}
