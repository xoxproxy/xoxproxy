// Package system provides host metrics for the dashboard's Server and
// Overview pages: identity, resource utilization, and network counters.
//
// Everything here is read-only observation of the host the control plane
// runs on. It never appears in the proxy data path and never gates
// availability: a failed metric is reported as unavailable, never as an
// error that breaks a page (GUIDE failure-isolation rules).
package system

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// publicIPRefresh bounds how often the outbound public-IP lookup runs.
// The lookup leaves the host; between refreshes the cached value serves.
const publicIPRefresh = time.Hour

// publicIPTimeout bounds the outbound lookup so a slow or firewalled
// egress cannot stall a dashboard request.
const publicIPTimeout = 3 * time.Second

// Identity is the static-ish host description of the Server page.
type Identity struct {
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`    // e.g. "linux"
	Platform   string `json:"platform"` // e.g. "debian 12"
	Kernel     string `json:"kernel"`   // e.g. "6.1.0-18-amd64"
	Arch       string `json:"arch"`     // runtime.GOARCH
	UptimeSec  uint64 `json:"uptime_seconds"`
	BootTime   time.Time `json:"boot_time"`
}

// Resources is a point-in-time utilization snapshot.
type Resources struct {
	// CPU: overall busy percent across cores.
	CPUPercent float64 `json:"cpu_percent"`
	// Cores and load averages for context.
	Cores       int     `json:"cores"`
	Load1       float64 `json:"load_1"`
	Load5       float64 `json:"load_5"`
	Load15      float64 `json:"load_15"`
	// Memory in bytes.
	MemTotal  uint64 `json:"mem_total"`
	MemUsed   uint64 `json:"mem_used"`
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
	// Disk for the volume holding the data directory, in bytes.
	DiskTotal uint64 `json:"disk_total"`
	DiskUsed  uint64 `json:"disk_used"`
	// Network counters since boot, in bytes (aggregate across interfaces,
	// loopback excluded).
	NetRxBytes uint64 `json:"net_rx_bytes"`
	NetTxBytes uint64 `json:"net_tx_bytes"`
}

// Provider serves host identity and utilization. The interface keeps the
// API handlers testable with a fake (the analytics seam pattern).
type Provider interface {
	Identity(ctx context.Context) (Identity, error)
	Resources(ctx context.Context) (Resources, error)
	// PublicIP returns the cached outbound-facing IP ("" when unknown
	// yet or egress is unavailable).
	PublicIP(ctx context.Context) string
}

// Local is the real provider: gopsutil on the local host. It is safe for
// concurrent use.
type Local struct {
	// DiskPath is the mount point whose utilization is reported (the
	// volume holding the database). Empty defaults to "/".
	DiskPath string

	mu       sync.Mutex
	publicIP string
	fetched  time.Time // zero = never
}

var _ Provider = (*Local)(nil)

// NewLocal builds the provider for the given data volume.
func NewLocal(diskPath string) *Local { return &Local{DiskPath: diskPath} }

func (l *Local) Identity(ctx context.Context) (Identity, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return Identity{}, err
	}
	hostname := info.Hostname
	if hostname == "" {
		// Hostname is cosmetic but central to the Server page; fall back
		// rather than serve an empty string.
		hostname = "unknown"
	}
	return Identity{
		Hostname:  hostname,
		OS:        info.OS,
		Platform:  info.Platform + " " + info.PlatformVersion,
		Kernel:    info.KernelVersion,
		Arch:      runtime.GOARCH,
		UptimeSec: info.Uptime,
		BootTime:  time.Unix(int64(info.BootTime), 0).UTC(),
	}, nil
}

func (l *Local) Resources(ctx context.Context) (Resources, error) {
	var res Resources
	var errs []error

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		res.MemTotal, res.MemUsed = vm.Total, vm.Used
	} else {
		errs = append(errs, err)
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		res.SwapTotal, res.SwapUsed = sw.Total, sw.Used
	} else {
		errs = append(errs, err)
	}

	path := l.DiskPath
	if path == "" {
		path = "/"
	}
	if du, err := disk.UsageWithContext(ctx, path); err == nil {
		res.DiskTotal, res.DiskUsed = du.Total, du.Used
	} else {
		errs = append(errs, err)
	}

	if counters, err := gnet.IOCountersWithContext(ctx, false); err == nil && len(counters) == 1 {
		res.NetRxBytes, res.NetTxBytes = counters[0].BytesRecv, counters[0].BytesSent
	} else if err != nil {
		errs = append(errs, err)
	}

	if avg, err := load.AvgWithContext(ctx); err == nil {
		res.Load1, res.Load5, res.Load15 = avg.Load1, avg.Load5, avg.Load15
	} else {
		errs = append(errs, err)
	}
	res.Cores = runtime.NumCPU()

	// CPU percent is sampled over a short window; on a busy host this
	// call is the slowest part, so a failure degrades to 0 rather than
	// failing the whole snapshot.
	if pct, err := cpu.PercentWithContext(ctx, 250*time.Millisecond, false); err == nil && len(pct) == 1 {
		res.CPUPercent = pct[0]
	}

	if len(errs) > 0 && res.MemTotal == 0 && res.DiskTotal == 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

// publicIPServices is the lookup chain: the first to answer wins. Plain
// text endpoints, GET only, response is the IP itself.
var publicIPServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
}

func (l *Local) PublicIP(ctx context.Context) string {
	l.mu.Lock()
	if l.fetched.IsZero() || time.Since(l.fetched) > publicIPRefresh {
		l.mu.Unlock()
		ip := lookupPublicIP(ctx)
		l.mu.Lock()
		if ip != "" {
			l.publicIP, l.fetched = ip, time.Now()
		} else {
			// Back off: retry at most once per refresh window even on
			// failure, so an offline host does not dial out per request.
			l.fetched = time.Now()
		}
		ip = l.publicIP
		l.mu.Unlock()
		return ip
	}
	ip := l.publicIP
	l.mu.Unlock()
	return ip
}

func lookupPublicIP(ctx context.Context) string {
	client := &http.Client{Timeout: publicIPTimeout}
	for _, url := range publicIPServices {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}
