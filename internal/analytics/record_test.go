package analytics

import (
	"testing"

	"github.com/xoxproxy/xoxproxy/internal/engine/threeproxy"
	"github.com/xoxproxy/xoxproxy/internal/store"
)

func TestClassifyProtocol(t *testing.T) {
	cases := []struct {
		name        string
		service     string
		requestText string
		want        string
	}{
		{"socks service is SOCKS5", "socks", "", store.StatSOCKS},
		{"CONNECT is HTTPS", "proxy", "CONNECT example.com:443", store.StatHTTPS},
		{"lowercase connect is HTTPS", "proxy", "connect example.com:443", store.StatHTTPS},
		{"GET is HTTP", "proxy", "GET http://example.com/ HTTP/1.1", store.StatHTTP},
		{"empty request is HTTP", "proxy", "", store.StatHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyProtocol(tc.service, tc.requestText); got != tc.want {
				t.Fatalf("ClassifyProtocol(%q, %q) = %q, want %q", tc.service, tc.requestText, got, tc.want)
			}
		})
	}
}

func TestFromUsage(t *testing.T) {
	rec := threeproxy.UsageRecord{
		UnixMillis:      1700000000000,
		Service:         "proxy",
		Username:        "alice",
		ClientIP:        "10.0.0.1",
		TargetIP:        "example.com",
		TargetPort:      443,
		ErrCode:         10,
		BytesToTarget:   100,
		BytesFromTarget: 900,
		RequestText:     "CONNECT example.com:443",
	}
	got := FromUsage(rec)
	if got.Username != "alice" || got.Protocol != store.StatHTTPS || got.Host != "example.com" || got.Port != 443 {
		t.Fatalf("FromUsage mis-mapped: %+v", got)
	}
	if !got.Blocked {
		t.Fatal("ErrCode 10 (quota) must map to Blocked")
	}
	if got.BytesIn != 900 || got.BytesOut != 100 {
		t.Fatalf("bytes swapped: in=%d out=%d", got.BytesIn, got.BytesOut)
	}
}
