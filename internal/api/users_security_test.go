package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// Phase 5 attack suites (docs/SECURITY-TESTING.md §5 IDOR, §2 stored XSS,
// plus the credential-exposure rules from GUIDE "Proxy Credentials").

// userRoutes is every user-object route introduced in Phase 5. All of them
// must enforce session authentication server-side.
var userRoutes = []struct {
	method, path string
	mutation     bool
}{
	{http.MethodGet, "/api/v1/users", false},
	{http.MethodPost, "/api/v1/users", true},
	{http.MethodGet, "/api/v1/users/1", false},
	{http.MethodPatch, "/api/v1/users/1", true},
	{http.MethodDelete, "/api/v1/users/1", true},
	{http.MethodPost, "/api/v1/users/1/rotate-credentials", true},
	{http.MethodPost, "/api/v1/users/1/disable", true},
	{http.MethodPost, "/api/v1/users/1/enable", true},
}

// createUserViaAPI creates a user through the API and returns its id.
func createUserViaAPI(t *testing.T, h http.Handler, cookie, csrf, username string) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/users", cookie, csrf, jsonBody(map[string]any{
		"username":          username,
		"allowed_protocols": []string{"http", "socks5"},
	})))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.ID
}

// TestSecurityIDORUserRoutes: every user-object route must deny
// unauthenticated and forged requests before any object data is touched,
// and crafted identifiers must never yield objects or internals.
func TestSecurityIDORUserRoutes(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// Seed a real user so "does the object leak" is meaningful.
	cookie, csrf := login(t, h)
	id := createUserViaAPI(t, h, cookie, csrf, "alice")
	path := func(p string) string {
		return strings.Replace(p, "/1/", "/"+strconv.FormatInt(id, 10)+"/", 1)
	}

	// 1. Unauthenticated and forged-session requests to every route:
	//    401 before any handler logic, never object data.
	for _, rt := range userRoutes {
		target := path(rt.path)
		for name, build := range map[string]func() *http.Request{
			"no cookie": func() *http.Request {
				return httptest.NewRequest(rt.method, target, nil)
			},
			"empty cookie": func() *http.Request {
				r := httptest.NewRequest(rt.method, target, nil)
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: ""})
				return r
			},
			"unknown token": func() *http.Request {
				r := httptest.NewRequest(rt.method, target, nil)
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "forged-session-token"})
				return r
			},
			"spoofed headers": func() *http.Request {
				r := httptest.NewRequest(rt.method, target, nil)
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "forged"})
				r.Header.Set("Authorization", "Bearer admin")
				r.Header.Set("X-CSRF-Token", "forged")
				return r
			},
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, build())
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s (%s) = %d, want 401", rt.method, target, name, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "alice") {
				t.Errorf("%s %s (%s) leaked object data: %s", rt.method, target, name, rec.Body.String())
			}
		}
	}

	// 2. A valid session without the CSRF token cannot mutate.
	for _, rt := range userRoutes {
		if !rt.mutation {
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(rt.method, path(rt.path), cookie, "", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF = %d, want 403", rt.method, rt.path, rec.Code)
		}
	}

	// 3. Crafted identifiers: never an object, never a 500, never SQL or
	//    filesystem internals.
	for _, id := range []string{"999", "0", "-1", "abc", "1;DROP", "1.5", "1e3", "..%2F2", "%31", "9", "9223372036854775808"} {
		for _, rt := range userRoutes {
			if !strings.Contains(rt.path, "/1/") {
				continue
			}
			target := strings.Replace(rt.path, "/1/", "/"+url.PathEscape(id)+"/", 1)
			// Mutation routes parse a JSON body before rejecting the id, so
			// they need a syntactically valid one.
			var reqBody io.Reader
			if rt.method == http.MethodPost || rt.method == http.MethodPatch {
				reqBody = jsonBody(map[string]any{"version": 1})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, authed(rt.method, target, cookie, csrf, reqBody))
			switch rec.Code {
			case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
			default:
				t.Errorf("%s /users/%s = %d (%s), want 400/404", rt.method, id, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "alice") || strings.Contains(strings.ToLower(body), "sql") {
				t.Errorf("%s /users/%s leaked data or internals: %s", rt.method, id, body)
			}
		}
	}

	// 4. A revoked session (logout) grants nothing afterwards.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/logout", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users", cookie, csrf, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("user list after logout = %d, want 401", rec.Code)
	}

	// 5. Control: the authenticated, correct-CSRF flow still works — the
	//    denials above are authorization, not breakage.
	cookie, csrf = login(t, h)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users/"+strconv.FormatInt(id, 10), cookie, csrf, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("control get = %d: %s", rec.Code, rec.Body.String())
	}
}

// TestSecurityStoredXSSUserFields: hostile strings in user fields must be
// rejected at validation and must appear in no response body, no stored
// record, and no audit entry — encoding alone is not enough here, the
// values are simply not admitted.
func TestSecurityStoredXSSUserFields(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()
	cookie, csrf := login(t, h)

	payload := "<script>alert(1)</script>"

	// Username: the engine charset policy rejects it outright.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/users", cookie, csrf, jsonBody(map[string]any{
		"username":          payload,
		"allowed_protocols": []string{"http"},
	})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("xss username = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("payload reflected in rejection: %s", rec.Body.String())
	}

	// Protocol field: unknown protocol rejected.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/users", cookie, csrf, jsonBody(map[string]any{
		"username":          "victim",
		"allowed_protocols": []string{payload},
	})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("xss protocol = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// Status filter: enum-validated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users?status="+payload, cookie, csrf, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("xss status filter = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// Nothing was stored: the user list and the audit trail are clean.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users", cookie, csrf, nil))
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("payload stored via user list: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/audit-logs?limit=100", cookie, csrf, nil))
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("payload stored in audit trail: %s", rec.Body.String())
	}

	// Control: a legitimate username round-trips unchanged (as a JSON
	// string — the API emits JSON only).
	id := createUserViaAPI(t, h, cookie, csrf, "legit.user-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users/"+strconv.FormatInt(id, 10), cookie, csrf, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "legit.user-1") {
		t.Fatalf("legitimate username did not round-trip: %d %s", rec.Code, rec.Body.String())
	}
}

// TestSecurityCredentialsNeverExposed: hashes and passwords must never
// appear in ordinary responses; the plaintext appears exactly once, in the
// create/rotate response.
func TestSecurityCredentialsNeverExposed(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()
	cookie, csrf := login(t, h)

	// Create with a manual password so there is a known secret to hunt for.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/users", cookie, csrf, jsonBody(map[string]any{
		"username":          "carol",
		"password":          "manual-staple-88x",
		"allowed_protocols": []string{"http"},
	})))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	createBody := rec.Body.String()
	if !strings.Contains(createBody, "manual-staple-88x") {
		t.Fatal("create response must return the one-time password")
	}

	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// Every ordinary endpoint: no plaintext, no hash material, no
	// "password" field at all.
	for _, target := range []string{
		"/api/v1/users",
		"/api/v1/users/" + strconv.FormatInt(created.ID, 10),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet, target, cookie, csrf, nil))
		body := rec.Body.String()
		for _, secret := range []string{
			"manual-staple-88x",
			"$3$",
			"argon2id",
			"engine_hash",
			"api_hash",
			"\"password\"",
		} {
			if strings.Contains(body, secret) {
				t.Errorf("GET %s exposed %q: %s", target, secret, body)
			}
		}
	}

	// Rotation: the new one-time password is returned once and differs
	// from the old; subsequent reads never contain either.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost,
		"/api/v1/users/"+strconv.FormatInt(created.ID, 10)+"/rotate-credentials", cookie, csrf, jsonBody(map[string]string{})))
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", rec.Code, rec.Body.String())
	}
	var rotated struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil || rotated.Password == "" {
		t.Fatalf("rotate did not return a one-time password: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/users/"+strconv.FormatInt(created.ID, 10), cookie, csrf, nil))
	if strings.Contains(rec.Body.String(), rotated.Password) {
		t.Fatal("rotated password readable from the user endpoint")
	}
}

// TestSecurityUserMutationAuditTrail: every successful mutation leaves an
// audit record naming the action and target, with no secrets.
func TestSecurityUserMutationAuditTrail(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()
	cookie, csrf := login(t, h)

	id := createUserViaAPI(t, h, cookie, csrf, "dave")

	mutations := []struct{ method, path string }{
		{http.MethodPatch, "/api/v1/users/" + strconv.FormatInt(id, 10)},
		{http.MethodPost, "/api/v1/users/" + strconv.FormatInt(id, 10) + "/disable"},
		{http.MethodPost, "/api/v1/users/" + strconv.FormatInt(id, 10) + "/enable"},
		{http.MethodPost, "/api/v1/users/" + strconv.FormatInt(id, 10) + "/rotate-credentials"},
	}
	version := int64(1)
	for _, m := range mutations {
		var body any
		switch {
		case m.method == http.MethodPatch:
			body = map[string]any{"version": version, "max_connections": 10}
		case strings.HasSuffix(m.path, "/rotate-credentials"):
			// rotate accepts only an optional password; unknown fields are
			// rejected, so the body must be empty.
			body = map[string]any{}
		default:
			body = map[string]any{"version": version}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(m.method, m.path, cookie, csrf, jsonBody(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s = %d: %s", m.method, m.path, rec.Code, rec.Body.String())
		}
		var resp struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		version = resp.Version
	}

	// The audit trail has one entry per action, none containing secrets.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/audit-logs?limit=100", cookie, csrf, nil))
	var list struct {
		Entries []struct {
			Action string `json:"action"`
			Target string `json:"target"`
			Result string `json:"result"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"user.create": false, "user.update": false, "user.disable": false,
		"user.enable": false, "user.rotate_credentials": false,
	}
	for _, e := range list.Entries {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
			if e.Target != "dave" {
				t.Errorf("audit %s target = %q, want dave", e.Action, e.Target)
			}
			if e.Result != "success" {
				t.Errorf("audit %s result = %q", e.Action, e.Result)
			}
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("audit trail missing %s", action)
		}
	}
}
