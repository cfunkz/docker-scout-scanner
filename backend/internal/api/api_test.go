package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/config"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

type env struct {
	t      *testing.T
	pub    *httptest.Server
	admin  *httptest.Server
	st     *store.Store
	pw     string
	client *http.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	ctx := context.Background()
	if err := Bootstrap(ctx, st, dir, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "initial-admin-password"))
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 || lines[0] != "admin" || len(lines[1]) < 12 {
		t.Fatalf("bootstrap file malformed: %q", raw)
	}
	cfg, _ := config.NewManager(ctx, st)
	s := New(st, cfg, nil, nil, config.Env{DataDir: dir, SecureCookie: false}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e := &env{t: t, pub: httptest.NewServer(s.PublicHandler()), admin: httptest.NewServer(s.AdminHandler()), st: st, pw: lines[1]}
	t.Cleanup(e.pub.Close)
	t.Cleanup(e.admin.Close)
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	return e
}

func (e *env) do(base, method, path, csrf string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestLoginFlowAndForcedPasswordChange(t *testing.T) {
	e := setup(t)
	if code, _ := e.do(e.pub.URL, "GET", "/api/images", "", nil); code != 401 {
		t.Fatalf("anonymous access should be refused, got %d", code)
	}
	if code, _ := e.do(e.pub.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "wrong-password"}); code != 401 {
		t.Fatalf("bad password should be 401, got %d", code)
	}
	code, out := e.do(e.pub.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": e.pw})
	if code != 200 || out["must_change"] != true {
		t.Fatalf("login failed: %d %v", code, out)
	}
	csrf := out["csrf"].(string)

	// Until the temporary password is changed, data endpoints are blocked.
	if code, _ := e.do(e.pub.URL, "GET", "/api/images", "", nil); code != 403 {
		t.Fatalf("must_change should block data, got %d", code)
	}
	// CSRF token is required for state changes.
	if code, _ := e.do(e.pub.URL, "POST", "/api/me/password", "", map[string]string{"current": e.pw, "new": "a-much-better-password"}); code != 403 {
		t.Fatalf("missing CSRF should be 403, got %d", code)
	}
	if code, out := e.do(e.pub.URL, "POST", "/api/me/password", csrf, map[string]string{"current": e.pw, "new": "short"}); code != 400 {
		t.Fatalf("weak password should be rejected: %d %v", code, out)
	}
	if code, out := e.do(e.pub.URL, "POST", "/api/me/password", csrf, map[string]string{"current": e.pw, "new": "a-much-better-password"}); code != 200 {
		t.Fatalf("password change failed: %d %v", code, out)
	}
	if code, out := e.do(e.pub.URL, "GET", "/api/me", "", nil); code != 200 || out["must_change"] != false {
		t.Fatalf("me after change: %d %v", code, out)
	}
	// The dashboard session is not valid on the admin listener.
	if code, _ := e.do(e.admin.URL, "GET", "/api/admin/users", "", nil); code != 401 {
		t.Fatalf("dashboard session must not work on admin port, got %d", code)
	}
	// Admin API is not mounted on the public handler at all.
	if code, _ := e.do(e.pub.URL, "GET", "/api/admin/users", "", nil); code != 404 {
		t.Fatalf("admin routes must not exist on public listener, got %d", code)
	}
	code, out = e.do(e.admin.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "a-much-better-password"})
	if code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	acsrf := out["csrf"].(string)
	if code, _ := e.do(e.admin.URL, "GET", "/api/admin/users", "", nil); code != 200 {
		t.Fatalf("admin users: %d", code)
	}
	// Viewers cannot sign in to the admin panel.
	code, out = e.do(e.admin.URL, "POST", "/api/admin/users", acsrf, map[string]string{"username": "viewer1", "role": "viewer"})
	if code != 200 || out["password"] == nil {
		t.Fatalf("create user: %d %v", code, out)
	}
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	if code, _ := e.do(e.admin.URL, "POST", "/api/auth/login", "", map[string]string{"username": "viewer1", "password": out["password"].(string)}); code != 403 {
		t.Fatalf("viewer must not log into admin, got %d", code)
	}
	// Logout invalidates the session server-side.
	code, out = e.do(e.pub.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "a-much-better-password"})
	if code != 200 {
		t.Fatal(code)
	}
	e.do(e.pub.URL, "POST", "/api/auth/logout", "", nil)
	if code, _ := e.do(e.pub.URL, "GET", "/api/images", "", nil); code != 401 {
		t.Fatalf("after logout should be 401, got %d", code)
	}
}

func TestLockoutAndCrossSite(t *testing.T) {
	e := setup(t)
	for i := 0; i < 5; i++ {
		e.do(e.pub.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "nope-nope-nope"})
	}
	// Correct password is refused while locked.
	if code, _ := e.do(e.pub.URL, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": e.pw}); code != 401 {
		t.Fatalf("locked account should refuse login, got %d", code)
	}
	req, _ := http.NewRequest("POST", e.pub.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site login should be blocked, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestStoreFindingsRoundTrip(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	im := &store.Image{ID: "sha256:" + strings.Repeat("a", 64), RepoTags: []string{"nginx:1"}, RepoDigests: []string{}, Containers: []store.ContainerRef{{Name: "web", State: "running"}}}
	if err := st.UpsertSeen(ctx, im); err != nil {
		t.Fatal(err)
	}
	id, _ := st.StartScan(ctx, im.ID, "nginx:1", "trivy", "test")
	fs := []*store.Finding{{Kind: "vuln", VulnID: "CVE-1", PkgName: "a", PkgVersion: "1", Severity: "CRITICAL", Risk: 90, KEV: true}}
	if err := st.FinishScan(ctx, &store.ScanSummary{ID: id, ImageID: im.ID, Critical: 1, KEV: 1, RiskMax: 90}, fs); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetImage(ctx, strings.Repeat("a", 12))
	if got == nil || got.Scan == nil || got.Scan.Critical != 1 {
		t.Fatalf("image lookup by short id failed: %+v", got)
	}
	vs, _ := st.FleetVulns(ctx, "CVE", 10)
	if len(vs) != 1 || vs[0].Images != 1 || vs[0].InUse != 1 || !vs[0].KEV {
		t.Fatalf("fleet view wrong: %+v", vs)
	}
	if err := st.TakeSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	tr, _ := st.Trend(ctx, 30)
	if len(tr) != 1 || tr[0].Critical != 1 {
		t.Fatalf("trend wrong: %+v", tr)
	}
}
