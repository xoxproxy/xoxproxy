// Package analytics turns the engine's traffic log into per-user traffic
// monitoring: live connection view, per-destination statistics, and the
// usage ledger. It runs entirely off the proxy data path — the engine
// writes its log file, this package tails that file — so a monitoring
// failure can never slow or stop proxy traffic (GUIDE performance rule).
//
// The pipeline is bounded at every stage:
//
//	log file → tailer (1 poll/s) → bounded queue (drop-on-full)
//	        → in-memory aggregator (capped destinations, capped ring)
//	        → batched flush (one SQLite transaction per interval)
//
// Nothing here performs a synchronous write on the request path, and every
// in-memory structure has a configured cap, so monitoring cannot exhaust a
// 1-vCPU VPS no matter how busy the proxy is.
package analytics

import (
	"strings"

	"github.com/xoxproxy/xoxproxy/internal/engine/threeproxy"
	"github.com/xoxproxy/xoxproxy/internal/store"
)

// Record is one observed proxy request: the monitoring view of a parsed
// engine log line. It carries destination metadata only — the control
// plane never captures request bodies or decrypted HTTPS content.
type Record struct {
	UnixMillis int64  // when the engine logged the request (completion time)
	Username   string // proxy user as the engine authenticated them ("-" = unauthenticated)
	Protocol   string // store.StatHTTP | StatHTTPS | StatSOCKS
	Host       string // destination hostname (or IP) exactly as the client requested it
	Port       int
	ClientIP   string
	Blocked    bool  // refused by policy or cut by quota (engine error != 0)
	BytesIn    int64 // downloaded from the target
	BytesOut   int64 // uploaded to the target
}

// FromUsage converts one parsed engine log record into a monitoring
// record, classifying the protocol. The engine's HTTP service carries
// both plain HTTP and HTTPS CONNECT; the request text distinguishes
// them. The SOCKS service is SOCKS5.
func FromUsage(rec threeproxy.UsageRecord) Record {
	return Record{
		UnixMillis: rec.UnixMillis,
		Username:   rec.Username,
		Protocol:   ClassifyProtocol(rec.Service, rec.RequestText),
		Host:       rec.TargetIP,
		Port:       rec.TargetPort,
		ClientIP:   rec.ClientIP,
		Blocked:    rec.ErrCode != 0,
		BytesIn:    rec.BytesFromTarget,
		BytesOut:   rec.BytesToTarget,
	}
}

// ClassifyProtocol maps (engine service, request text) onto the protocol
// vocabulary of the destination stats. The SOCKS service is always SOCKS5;
// within the HTTP service, a CONNECT method means TLS tunnelling.
func ClassifyProtocol(service, requestText string) string {
	if service == "socks" {
		return store.StatSOCKS
	}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(requestText)), "CONNECT") {
		return store.StatHTTPS
	}
	return store.StatHTTP
}
