package threeproxy

import (
	"strings"
	"testing"

	"github.com/xoxproxy/xoxproxy/internal/engine"
)

func testSettings() Settings {
	return Settings{
		ConfigFile:  "/etc/xoxproxy/engine/3proxy.cfg",
		PidFile:     "/run/xoxproxy-engine/3proxy.pid",
		CounterFile: "/var/lib/xoxproxy-engine/counters.3cf",
		LogFile:     "/var/log/xoxproxy-engine/traffic.log",
		HTTPPort:    3128,
		SOCKS5Port:  1080,
		MaxConns:    500,
		Rotate:      14,
		Nameservers: []string{"1.1.1.1", "8.8.8.8"},
	}
}

func hashFor(t *testing.T, password string) string {
	t.Helper()
	h, err := NewEngineHash(password)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// validState is deterministic: fixed salts, so the same call renders
// byte-identical config across invocations (deploy idempotency).
func validState(t *testing.T) engine.State {
	t.Helper()
	return engine.State{
		Users: []engine.User{
			{
				Username:     "alice",
				EngineHash:   CRHash("correct-staple-9x", "fixedsaltalice1"),
				RecordNumber: 1,
				Protocols:    []engine.Protocol{engine.ProtoHTTP, engine.ProtoSOCKS5},
				DownloadBPS:  20 * 1000 * 1000,
				UploadBPS:    10 * 1000 * 1000,
				Quota: &engine.Quota{
					Period:     engine.PeriodMonthly,
					LimitBytes: 100 * engine.MiB,
					Direction:  engine.DirAll,
				},
			},
			{
				Username:     "bob",
				EngineHash:   CRHash("a-newer-staple-3", "fixedsaltbob000"),
				RecordNumber: 2,
				Protocols:    []engine.Protocol{engine.ProtoHTTP, engine.ProtoSOCKS5},
			},
		},
	}
}

func TestRenderProducesExpectedLayout(t *testing.T) {
	cfg, err := Render(validState(t), testSettings())
	if err != nil {
		t.Fatal(err)
	}

	// Every line that must be present, with exact arguments where
	// correctness depends on them (verified 3proxy semantics).
	mustContain := []string{
		"auth strong\n",
		"config \"/etc/xoxproxy/engine/3proxy.cfg\"\n",
		"pidfile \"/run/xoxproxy-engine/3proxy.pid\"\n",
		"nserver 1.1.1.1\n",
		"nscache 65535\n",
		"maxconn 500\n",
		"log \"/var/log/xoxproxy-engine/traffic.log\" D\n",
		"rotate 14\n",
		"logformat \"G%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T\"\n",
		"counter \"/var/lib/xoxproxy-engine/counters.3cf\"\n",
		"bandlimin 20000000 alice\n",
		"bandlimout 10000000 alice\n",
		"countall 1 M 100 alice\n",
		"proxy -p3128\n",
		"socks -p1080\n",
	}
	for _, want := range mustContain {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered config missing %q\n---\n%s---", want, cfg)
		}
	}

	// No user-configurable hash is rendered unquoted.
	if !strings.Contains(cfg, `users "alice:CR:$3$`) {
		t.Errorf("alice not rendered as quoted CR entry\n---\n%s---", cfg)
	}
	if strings.Contains(cfg, "noforce") {
		t.Error("noforce must never be emitted (breaks revocation)")
	}
	// No cleartext password may appear.
	if strings.Contains(cfg, "correct-staple-9x") || strings.Contains(cfg, "a-newer-staple-3") {
		t.Error("cleartext password leaked into engine config")
	}
	// Sorted order: alice before bob.
	if strings.Index(cfg, "allow alice") > strings.Index(cfg, "allow bob") {
		t.Errorf("users not sorted by name\n%s", cfg)
	}
	// bob (no limits) gets allow lines but no limit lines.
	for _, forbidden := range []string{"bandlimin 0 bob", "countall 2", "countin 2", "countout 2"} {
		if strings.Contains(cfg, forbidden) {
			t.Errorf("unlimited user rendered a limit: %q", forbidden)
		}
	}
	if strings.Count(cfg, "allow bob\n") != 2 {
		t.Errorf("allow bob should appear once per service, got %d", strings.Count(cfg, "allow bob\n"))
	}
}

func TestRenderDeterministicAndIdempotent(t *testing.T) {
	state := validState(t)
	st := testSettings()
	a, err := Render(state, st)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(state, st)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same state rendered differently — deploys would not be idempotent")
	}
}

func TestRenderEmptyUsersIsNeverOpenProxy(t *testing.T) {
	cfg, err := Render(engine.State{}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	// auth strong + no users in the table + non-empty ACL (implicit
	// deny) — but even if ACL were empty, strong auth refuses everyone.
	if !strings.Contains(cfg, "auth strong\n") {
		t.Fatalf("empty state dropped auth strong:\n%s", cfg)
	}
	if strings.Contains(cfg, "auth none") || strings.Contains(cfg, "auth iponly") {
		t.Fatalf("empty state weakened auth:\n%s", cfg)
	}
	if strings.Contains(cfg, "users ") {
		t.Fatalf("empty state rendered users:\n%s", cfg)
	}
}

func TestRenderQuotaDirectionsAndFloor(t *testing.T) {
	base := validState(t)
	base.Users = []engine.User{
		{
			Username:     "dave",
			EngineHash:   hashFor(t, "some-long-password-1"),
			RecordNumber: 7,
			Quota: &engine.Quota{
				Period:     engine.PeriodDaily,
				LimitBytes: 3*engine.MiB + 512*1024, // 3.5 MiB -> renders as 3 MiB
				Direction:  engine.DirIn,
			},
		},
	}
	cfg, err := Render(base, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "countin 7 D 3 dave\n") {
		t.Errorf("download quota not floored to whole MiB as expected:\n%s", cfg)
	}
}

func TestRenderProtocolFiltering(t *testing.T) {
	state := validState(t)
	// bob is HTTP-only: he must appear under proxy but not socks.
	state.Users[1].Protocols = []engine.Protocol{engine.ProtoHTTP}
	cfg, err := Render(state, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(cfg, "allow bob\n") != 1 {
		t.Errorf("HTTP-only user allow count = %d, want 1 (proxy only):\n%s", strings.Count(cfg, "allow bob\n"), cfg)
	}
	// alice (both protocols) still appears once per service.
	if strings.Count(cfg, "allow alice\n") != 2 {
		t.Errorf("dual-protocol user allow count = %d, want 2", strings.Count(cfg, "allow alice\n"))
	}
	// The socks section must not mention bob between its flush and the
	// socks directive.
	socksStart := strings.Index(cfg, "# --- SOCKS5 proxy ---")
	socksSvc := cfg[socksStart:]
	if strings.Contains(socksSvc, "allow bob") {
		t.Errorf("HTTP-only user allowed on SOCKS:\n%s", socksSvc)
	}

	// A user with no protocols gets no allow lines anywhere: no access,
	// fail closed.
	state.Users[1].Protocols = nil
	cfg, err = Render(state, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "allow bob") {
		t.Error("protocol-less user received access")
	}
}

func TestRenderRejectsBadSettings(t *testing.T) {
	for name, mutate := range map[string]func(*Settings){
		"relative config path":  func(s *Settings) { s.ConfigFile = "engine/3proxy.cfg" },
		"same ports":            func(s *Settings) { s.SOCKS5Port = s.HTTPPort },
		"http port zero":        func(s *Settings) { s.HTTPPort = 0 },
		"bad nameserver":        func(s *Settings) { s.Nameservers = []string{"not-an-ip"} },
		"nameserver injection":  func(s *Settings) { s.Nameservers = []string{"1.1.1.1\nallow *"} },
		"negative maxconn":      func(s *Settings) { s.MaxConns = -1 },
		"negative rotate":       func(s *Settings) { s.Rotate = -1 },
		"config path traversal": func(s *Settings) { s.ConfigFile = "/etc/xoxproxy/../../tmp/x" },
	} {
		st := testSettings()
		mutate(&st)
		if _, err := Render(validState(t), st); err == nil {
			t.Errorf("%s: render accepted invalid settings", name)
		}
	}
}

// --- attack cases (docs/SECURITY-TESTING.md: engine config injection) ---

// TestSecurityConfigInjectionViaUsername verifies that no hostile
// username can inject directives into the engine configuration. This is
// the engine-side equivalent of command injection: the config file is
// the data plane's program.
func TestSecurityConfigInjectionViaUsername(t *testing.T) {
	payloads := []string{
		"alice\nallow *",         // newline: new directive
		"alice:CL:backdoor",      // colon: rewrites the users entry
		"al ice",                 // whitespace: token splitting
		`alice" allow *`,         // quote escape
		"alice\tadmin",           // tab
		"alice#comment",          // comment smuggling
		"x",                      // too short? no — valid; control case below
		"-alice",                 // leading dash
		".alice",                 // leading dot
		"alice\nusers root:CL:x", // newline + new users
		"\x00alice",              // NUL
		"alice\x7f",              // DEL control char
		"café",                   // non-ASCII
		strings.Repeat("a", 65),  // over length
	}
	for _, p := range payloads {
		if p == "x" {
			continue // single-char alphanumeric is valid by policy
		}
		if err := engine.ValidateUsername(p); err == nil {
			t.Errorf("username %q passed validation", p)
		}
		state := engine.State{Users: []engine.User{{Username: p, EngineHash: hashFor(t, "pw-long-enough-1"), RecordNumber: 1}}}
		if _, err := Render(state, testSettings()); err == nil {
			t.Errorf("Render accepted hostile username %q", p)
		}
	}

	// Control: the policy admits ordinary names.
	for _, ok := range []string{"x", "alice", "user.name", "user_name", "user-1", "A1.b2-c3"} {
		if err := engine.ValidateUsername(ok); err != nil {
			t.Errorf("username %q should be valid: %v", ok, err)
		}
	}
}

// TestSecurityConfigInjectionViaHash verifies the EngineHash field —
// the only other attacker-influenced string reaching the config —
// cannot smuggle config syntax.
func TestSecurityConfigInjectionViaHash(t *testing.T) {
	payloads := []string{
		"$3$salt$hash\" allow *",
		"$3$salt$hash\nallow *",
		"$3$salt$hash:CL:backdoor",
		"$3$sa lt$AAAAAAAAAAAAAAAAAAAAAA",
		"$3$salt$AAAAAAAAAAAAAAAAAAAAAA allow *",
		"",
		"$3$$AAAAAAAAAAAAAAAAAAAAAA",
		"CL:plaintext",
		"$3$salt$" + strings.Repeat("A", 21), // short digest encoding
		"$3$salt$" + strings.Repeat("A", 23), // long digest encoding
	}
	for _, p := range payloads {
		state := validState(t)
		state.Users[0].EngineHash = p
		if _, err := Render(state, testSettings()); err == nil {
			t.Errorf("Render accepted hostile engine hash %q", p)
		}
	}
}

// TestSecurityQuotaCannotExceedConfigured verifies the rendered
// megabyte figure never exceeds the configured byte limit (floor, not
// round) and that absurd limits are rejected rather than overflowing.
func TestSecurityQuotaCannotExceedConfigured(t *testing.T) {
	// Below the enforcement granularity: rejected outright.
	state := validState(t)
	state.Users = []engine.User{{
		Username:     "eve",
		EngineHash:   hashFor(t, "long-enough-password"),
		RecordNumber: 3,
		Quota:        &engine.Quota{Period: engine.PeriodDaily, LimitBytes: 512 * 1024, Direction: engine.DirAll},
	}}
	if err := state.Validate(); err == nil {
		t.Fatal("512 KiB quota accepted below 1 MiB granularity")
	}

	// A fractional-megabyte quota is floored, never rounded up.
	state.Users[0].Quota.LimitBytes = 2*engine.MiB + 999999
	cfg, err := Render(state, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "countall 3 D 2 eve\n") {
		t.Errorf("quota not floored:\n%s", cfg)
	}
	if strings.Contains(cfg, "countall 3 D 3") {
		t.Error("quota rendered above configured limit")
	}
}

func TestRenderRecordNumberZeroRejected(t *testing.T) {
	state := validState(t)
	state.Users[1].RecordNumber = 0 // would silently drop quota persistence
	if err := state.Validate(); err == nil {
		t.Fatal("record number 0 accepted")
	}
	state.Users[1].RecordNumber = 1 // duplicate of alice
	if err := state.Validate(); err == nil {
		t.Fatal("duplicate record number accepted")
	}
}
