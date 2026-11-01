package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

const bcryptCost = 12

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
)

// dummyHash makes login take the same time whether or not the user exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcryptCost)

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(b), err
}

func checkPasswordPolicy(pw, username string) error {
	if utf8.RuneCountInString(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	if strings.EqualFold(pw, username) {
		return errors.New("password must differ from the username")
	}
	return nil
}

// Bootstrap creates the first admin account. The password comes from
// ADMIN_PASSWORD or is generated, logged once and written to a 0600 file.
func Bootstrap(ctx context.Context, st *store.Store, dataDir string, logf func(string, ...any)) error {
	user := os.Getenv("ADMIN_USER")
	if user == "" {
		user = "admin"
	}
	envPW := os.Getenv("ADMIN_PASSWORD")
	if st.UserCount(ctx) > 0 {
		if envPW != "" {
			return applyEnvPassword(ctx, st, user, envPW, logf)
		}
		// Existing data volume: no new password is generated. Say so, so a
		// reinstall on top of an old volume isn't a silent dead end.
		logf("admin account already exists (existing data volume), no new password generated",
			"forgot_password", "docker compose exec scanner scanner reset-password admin",
			"start_fresh", "docker compose down -v (deletes all scan data)")
		return nil
	}
	pw := envPW
	mustChange := false
	if pw == "" {
		pw = randToken(15)
		mustChange = true
	} else if err := checkPasswordPolicy(pw, user); err != nil {
		return err
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, user, h, "admin", mustChange); err != nil {
		return err
	}
	if mustChange {
		p := filepath.Join(dataDir, "initial-admin-password")
		_ = os.WriteFile(p, []byte(user+"\n"+pw+"\n"), 0o600)
		logf("created admin account", "user", user, "password", pw, "also_written_to", p, "note", "you will be asked to change it on first login")
	} else {
		rememberEnvPassword(ctx, st, envPW)
		logf("created admin account from ADMIN_PASSWORD", "user", user)
	}
	return nil
}

// envPasswordKey stores a bcrypt hash of the last ADMIN_PASSWORD that was
// applied, so a changed value in .env is applied once on the next start and
// a password changed later in the web UI isn't overwritten on every restart.
const envPasswordKey = "env_admin_password"

func rememberEnvPassword(ctx context.Context, st *store.Store, pw string) {
	if h, err := HashPassword(pw); err == nil {
		st.SetSetting(ctx, envPasswordKey, h)
	}
}

func applyEnvPassword(ctx context.Context, st *store.Store, user, pw string, logf func(string, ...any)) error {
	if old, ok := st.GetSetting(ctx, envPasswordKey); ok && bcrypt.CompareHashAndPassword([]byte(old), []byte(pw)) == nil {
		return nil // already applied; the web UI owns the password now
	}
	if err := checkPasswordPolicy(pw, user); err != nil {
		return fmt.Errorf("ADMIN_PASSWORD: %w", err)
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	u, _ := st.UserByName(ctx, user)
	if u == nil {
		if _, err := st.CreateUser(ctx, user, h, "admin", false); err != nil {
			return err
		}
	} else {
		if err := st.SetPassword(ctx, u.ID, h, false); err != nil {
			return err
		}
		st.LoginOK(ctx, u.ID) // clear lockout
		st.DeleteUserSessions(ctx, u.ID, "")
		if u.Role != "admin" {
			st.SetRole(ctx, u.ID, "admin")
		}
	}
	rememberEnvPassword(ctx, st, pw)
	st.Audit(ctx, "system", "", "password_from_env", user)
	logf("admin password set from ADMIN_PASSWORD in .env", "user", user,
		"note", "applied once; change it in the web UI afterwards, or change ADMIN_PASSWORD again")
	return nil
}

// ---------- login rate limiting ----------

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string][]time.Time{}} }

// allow permits `n` attempts per `per` for a key.
func (l *limiter) allow(key string, n int, per time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	keep := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < per {
			keep = append(keep, t)
		}
	}
	if len(keep) >= n {
		l.hits[key] = keep
		return false
	}
	l.hits[key] = append(keep, now)
	if len(l.hits) > 10000 { // bound memory under a spray
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > per {
				delete(l.hits, k)
			}
		}
	}
	return true
}

// ---------- sessions ----------

// secure reports whether the browser reached us over HTTPS. nginx always says
// https on its TLS ports; behind a TLS-terminating proxy on the plain port
// (HTTP_MODE=proxy, e.g. Runtipi's Traefik) it passes the proxy's
// X-Forwarded-Proto through, so plain-http LAN access still gets a cookie.
func (s *Server) secure(r *http.Request) bool {
	return s.env.SecureCookie && r.Header.Get("X-Forwarded-Proto") != "http"
}

func (s *Server) cookieName(r *http.Request, scope string) string {
	base := "dss"
	if scope == "admin" {
		base = "dsa"
	}
	if s.secure(r) {
		return "__Host-" + base
	}
	return base
}

// sessionSeconds is the idle timeout: the dashboard uses the setting, the
// admin panel is capped at 8 hours.
func (s *Server) sessionSeconds(scope string) int64 {
	hours := s.cfg.Get().SessionHours
	if scope == "admin" {
		hours = min(hours, 8)
	}
	return int64(hours) * 3600
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, scope, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(r, scope),
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) loadSession(w http.ResponseWriter, r *http.Request, scope string) (*store.Session, *store.User) {
	c, err := r.Cookie(s.cookieName(r, scope))
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return nil, nil
	}
	h := hashToken(c.Value)
	se, err := s.st.GetSession(r.Context(), h)
	if err != nil || se == nil || se.Scope != scope || se.ExpiresAt < time.Now().Unix() {
		return nil, nil
	}
	u, err := s.st.UserByID(r.Context(), se.UserID)
	if err != nil || u == nil {
		return nil, nil
	}
	if scope == "admin" && u.Role != "admin" {
		return nil, nil
	}
	// Sliding expiry, written at most once a minute.
	if time.Now().Unix()-se.LastSeen > 60 {
		secs := s.sessionSeconds(scope)
		s.st.TouchSession(r.Context(), h, time.Now().Unix()+secs)
		if w != nil {
			s.setSessionCookie(w, r, scope, c.Value, int(secs)) // keep the browser cookie in step
		}
	}
	return se, u
}

// auth wraps a handler: it requires a session for the listener's scope,
// checks the role, enforces CSRF on unsafe methods, and blocks everything
// but password change while a password change is pending.
func (s *Server) auth(scope string, role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "+tokenPrefix) {
			s.tokenAuth(scope, role, h, w, r)
			return
		}
		se, u := s.loadSession(w, r, scope)
		if se == nil {
			if scope == "dashboard" && role == "viewer" && !s.cfg.Get().RequireLogin {
				h(w, r)
				return
			}
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if role == "admin" && u.Role != "admin" {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "cross-site request blocked")
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(se.CSRF)) != 1 {
				writeErr(w, http.StatusForbidden, "bad CSRF token")
				return
			}
		}
		if u.MustChange && !strings.HasPrefix(r.URL.Path, "/api/me") && r.URL.Path != "/api/auth/logout" {
			writeErr(w, http.StatusForbidden, "password change required")
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, se)
		ctx = context.WithValue(ctx, ctxUser, u)
		h(w, r.WithContext(ctx))
	}
}

// sameOrigin uses Fetch Metadata where the browser sends it.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func currentSession(r *http.Request) *store.Session {
	se, _ := r.Context().Value(ctxSession).(*store.Session)
	return se
}

func actor(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.Username
	}
	return "anonymous"
}

// clientIP trusts X-Real-IP because the backend is only reachable from the
// bundled nginx, which sets it from the (optionally proxy-aware) real IP.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" && len(ip) < 64 {
		return ip
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

func (s *Server) handleLogin(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "cross-site request blocked")
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Code     string `json:"code"` // 2FA code or recovery code
		}
		if !readJSON(w, r, &body) {
			return
		}
		ip := clientIP(r)
		if !s.lim.allow("ip:"+ip, 10, time.Minute) || !s.lim.allow("user:"+strings.ToLower(body.Username), 20, 10*time.Minute) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
			return
		}
		cfg := s.cfg.Get()
		ctx := r.Context()
		u, _ := s.st.UserByName(ctx, strings.TrimSpace(body.Username))
		hash := dummyHash
		if u != nil {
			hash = []byte(u.PassHash)
		}
		pwOK := len(body.Password) <= 72 && bcrypt.CompareHashAndPassword(hash, []byte(body.Password)) == nil
		now := time.Now().Unix()
		if u == nil || !pwOK || u.LockedUntil > now {
			if u != nil && u.LockedUntil <= now {
				failed := u.Failed + 1
				var until int64
				if failed >= cfg.LockoutAttempts {
					until, failed = now+int64(cfg.LockoutMinutes)*60, 0
				}
				s.st.LoginFailed(ctx, u.ID, failed, until)
			}
			s.st.Audit(ctx, body.Username, ip, "login_failed", scope)
			writeErr(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		if scope == "admin" && u.Role != "admin" {
			s.st.Audit(ctx, u.Username, ip, "login_denied", "admin panel needs the admin role")
			writeErr(w, http.StatusForbidden, "this account cannot use the admin panel")
			return
		}
		if t, _ := s.st.GetTOTP(ctx, u.ID); t != nil && t.Enabled {
			if strings.TrimSpace(body.Code) == "" {
				// Password was right; ask for the second factor. No session yet.
				writeJSON(w, 200, map[string]any{"totp_required": true})
				return
			}
			if !s.checkSecondFactor(r, u.ID, t.Secret, body.Code) {
				failed := u.Failed + 1
				var until int64
				if failed >= cfg.LockoutAttempts {
					until, failed = now+int64(cfg.LockoutMinutes)*60, 0
				}
				s.st.LoginFailed(ctx, u.ID, failed, until)
				s.st.Audit(ctx, u.Username, ip, "login_failed", scope+" (2fa code)")
				writeJSON(w, 401, map[string]any{"error": "wrong or already used code", "totp_required": true})
				return
			}
		}
		s.st.LoginOK(ctx, u.ID)
		token := randToken(32)
		secs := s.sessionSeconds(scope)
		se := &store.Session{
			TokenHash: hashToken(token), UserID: u.ID, Scope: scope, CSRF: randToken(24),
			CreatedAt: now, ExpiresAt: now + secs, LastSeen: now,
			IP: ip, UserAgent: truncate(r.UserAgent(), 200),
		}
		if err := s.st.CreateSession(ctx, se); err != nil {
			writeErr(w, 500, "could not create session")
			return
		}
		// A persistent cookie, so a browser restart doesn't sign you out. The
		// server still enforces the idle timeout and refreshes both.
		s.setSessionCookie(w, r, scope, token, int(secs))
		s.st.Audit(ctx, u.Username, ip, "login", scope)
		writeJSON(w, 200, map[string]any{"user": u.Username, "role": u.Role, "csrf": se.CSRF, "must_change": u.MustChange})
	}
}

func (s *Server) handleLogout(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.cookieName(r, scope)); err == nil {
			s.st.DeleteSession(r.Context(), hashToken(c.Value))
		}
		s.setSessionCookie(w, r, scope, "", -1)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func (s *Server) handleMe(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		se, u := s.loadSession(w, r, scope)
		if se == nil {
			cfg := s.cfg.Get()
			writeJSON(w, 200, map[string]any{"user": nil, "require_login": scope == "admin" || cfg.RequireLogin})
			return
		}
		writeJSON(w, 200, map[string]any{"user": u.Username, "role": u.Role, "csrf": se.CSRF, "must_change": u.MustChange, "expires_at": se.ExpiresAt})
	}
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u := currentUser(r)
	if u == nil {
		writeErr(w, 401, "login required")
		return
	}
	if !s.lim.allow("pw:"+u.Username, 5, 10*time.Minute) {
		writeErr(w, 429, "too many attempts")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(body.Current)) != nil {
		writeErr(w, 400, "current password is wrong")
		return
	}
	if body.New == body.Current {
		writeErr(w, 400, "choose a new password")
		return
	}
	if err := checkPasswordPolicy(body.New, u.Username); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	h, err := HashPassword(body.New)
	if err != nil {
		writeErr(w, 500, "hash failed")
		return
	}
	if err := s.st.SetPassword(r.Context(), u.ID, h, false); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// Sign out every other session of this user.
	s.st.DeleteUserSessions(r.Context(), u.ID, currentSession(r).TokenHash)
	_ = os.Remove(filepath.Join(s.env.DataDir, "initial-admin-password"))
	s.st.Audit(r.Context(), u.Username, clientIP(r), "password_changed", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// RandomPassword returns a 20-character URL-safe random password.
func RandomPassword() string { return randToken(15) }
