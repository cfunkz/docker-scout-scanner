package api

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 seed, truncated to 6 digits.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(secret, ts/30); got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
	}
	now := time.Unix(1234567890, 0)
	if totpMatch(secret, "005924", now) == 0 || totpMatch(secret, "000000", now) != 0 || totpMatch(secret, "12345", now) != 0 {
		t.Fatal("totpMatch")
	}
}

// login signs in with a fresh cookie jar and returns the CSRF token.
func (e *env) login(base, user, pw, code string) (int, map[string]any) {
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	body := map[string]string{"username": user, "password": pw}
	if code != "" {
		body["code"] = code
	}
	return e.do(base, "POST", "/api/auth/login", "", body)
}

func (e *env) bearer(base, method, path, tok string) int {
	req, _ := http.NewRequest(method, base+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestTwoFactorAndTokens(t *testing.T) {
	e := setup(t)
	const pw = "a-much-better-password"
	_, out := e.login(e.pub.URL, "admin", e.pw, "")
	if c, o := e.do(e.pub.URL, "POST", "/api/me/password", out["csrf"].(string), map[string]string{"current": e.pw, "new": pw}); c != 200 {
		t.Fatalf("pw change %d %v", c, o)
	}
	_, out = e.login(e.pub.URL, "admin", pw, "")
	csrf := out["csrf"].(string)

	// --- 2FA setup ---
	if c, _ := e.do(e.pub.URL, "POST", "/api/me/2fa/setup", csrf, map[string]string{"password": "nope"}); c != 400 {
		t.Fatalf("setup with wrong password should fail, got %d", c)
	}
	c, out := e.do(e.pub.URL, "POST", "/api/me/2fa/setup", csrf, map[string]string{"password": pw})
	if c != 200 || out["secret"] == nil || out["qr"] == nil {
		t.Fatalf("setup: %d %v", c, out)
	}
	secret := out["secret"].(string)
	step := time.Now().Unix() / 30
	if c, _ := e.do(e.pub.URL, "POST", "/api/me/2fa/enable", csrf, map[string]string{"code": "000000"}); c != 400 {
		t.Fatalf("enable with wrong code should fail, got %d", c)
	}
	c, out = e.do(e.pub.URL, "POST", "/api/me/2fa/enable", csrf, map[string]string{"code": totpCode(secret, step)})
	if c != 200 {
		t.Fatalf("enable: %d %v", c, out)
	}
	recovery := out["recovery_codes"].([]any)
	if len(recovery) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(recovery))
	}

	// --- 2FA login ---
	if c, out := e.login(e.pub.URL, "admin", pw, ""); c != 200 || out["totp_required"] != true || out["csrf"] != nil {
		t.Fatalf("password alone must not sign in: %d %v", c, out)
	}
	if c, _ := e.do(e.pub.URL, "GET", "/api/images", "", nil); c != 401 {
		t.Fatalf("no session expected after first step, got %d", c)
	}
	// The code used to enable 2FA can't be replayed.
	if c, _ := e.login(e.pub.URL, "admin", pw, totpCode(secret, step)); c != 401 {
		t.Fatalf("replayed code must fail, got %d", c)
	}
	if c, out := e.login(e.pub.URL, "admin", pw, recovery[0].(string)); c != 200 || out["csrf"] == nil {
		t.Fatalf("recovery code login: %d %v", c, out)
	}
	if c, _ := e.login(e.pub.URL, "admin", pw, recovery[0].(string)); c != 401 {
		t.Fatalf("recovery codes are single use, got %d", c)
	}
	e.st.LoginOK(context.Background(), 1) // clear failure counter
	_, out = e.login(e.admin.URL, "admin", pw, recovery[1].(string))
	acsrf := out["csrf"].(string)

	// --- tokens ---
	c, out = e.do(e.admin.URL, "POST", "/api/me/tokens", acsrf, map[string]any{"name": "homepage", "scope": "read"})
	if c != 200 {
		t.Fatalf("create read token: %d %v", c, out)
	}
	read := out["token"].(string)
	_, out = e.do(e.admin.URL, "POST", "/api/me/tokens", acsrf, map[string]any{"name": "ci", "scope": "admin", "days": 30})
	adm := out["token"].(string)

	cases := []struct {
		base, method, path, tok string
		want                    int
	}{
		{e.pub.URL, "GET", "/api/images", read, 200},
		{e.admin.URL, "GET", "/api/images", read, 200},
		{e.admin.URL, "GET", "/api/admin/users", read, 403},
		{e.admin.URL, "GET", "/api/admin/users", adm, 200},
		{e.admin.URL, "GET", "/api/admin/tokens", adm, 200},
		{e.pub.URL, "GET", "/api/images", adm, 200},
		{e.pub.URL, "GET", "/api/me/tokens", read, 403},
		{e.admin.URL, "POST", "/api/me/password", adm, 403},
		{e.pub.URL, "GET", "/api/images", "dss_not-a-real-token", 401},
		{e.pub.URL, "GET", "/api/images", read + "x", 401},
	}
	for _, tc := range cases {
		if got := e.bearer(tc.base, tc.method, tc.path, tc.tok); got != tc.want {
			t.Errorf("%s %s with token: got %d want %d", tc.method, tc.path, got, tc.want)
		}
	}

	// Demoting the owner disables the admin token's admin rights.
	_, _ = e.st.CreateUser(context.Background(), "admin2", "x", "admin", false)
	_ = e.st.SetRole(context.Background(), 1, "viewer")
	if got := e.bearer(e.admin.URL, "GET", "/api/admin/users", adm); got != 403 {
		t.Errorf("token of a demoted admin: got %d want 403", got)
	}
	_ = e.st.SetRole(context.Background(), 1, "admin")

	// Revoked tokens stop working.
	var list []map[string]any
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/me/tokens", nil)
	resp, _ := e.client.Do(req)
	_ = jsonDecode(resp, &list)
	for _, tk := range list {
		if tk["name"] == "homepage" {
			id := int(tk["id"].(float64))
			if c, _ := e.do(e.admin.URL, "DELETE", "/api/me/tokens/"+itoa(id), acsrf, nil); c != 200 {
				t.Fatalf("delete token %d", c)
			}
		}
	}
	if got := e.bearer(e.pub.URL, "GET", "/api/images", read); got != 401 {
		t.Errorf("revoked token: got %d want 401", got)
	}
}

func jsonDecode(resp *http.Response, v any) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestEnvPasswordAppliedOnce(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	boot := func() {
		if err := Bootstrap(ctx, e.st, t.TempDir(), func(string, ...any) {}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ADMIN_PASSWORD", "password-from-dotenv")
	boot()
	if c, _ := e.login(e.pub.URL, "admin", "password-from-dotenv", ""); c != 200 {
		t.Fatalf("env password not applied: %d", c)
	}
	// Changed in the UI: a restart with the same .env must not undo it.
	_, out := e.login(e.pub.URL, "admin", "password-from-dotenv", "")
	if c, _ := e.do(e.pub.URL, "POST", "/api/me/password", out["csrf"].(string), map[string]string{"current": "password-from-dotenv", "new": "changed-in-the-web-ui"}); c != 200 {
		t.Fatal("change")
	}
	boot()
	if c, _ := e.login(e.pub.URL, "admin", "changed-in-the-web-ui", ""); c != 200 {
		t.Fatalf("UI password lost after restart: %d", c)
	}
	// A new value in .env wins once.
	t.Setenv("ADMIN_PASSWORD", "another-dotenv-password")
	boot()
	if c, _ := e.login(e.pub.URL, "admin", "another-dotenv-password", ""); c != 200 {
		t.Fatalf("new env password not applied: %d", c)
	}
}

func TestSessionCookiePersistent(t *testing.T) {
	e := setup(t)
	resp, err := http.Post(e.pub.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+e.pw+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "dss" && c.MaxAge > 3600 {
			return
		}
	}
	t.Fatalf("no persistent session cookie: %v", resp.Header.Values("Set-Cookie"))
}
