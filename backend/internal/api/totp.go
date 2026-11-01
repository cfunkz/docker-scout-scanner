package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rsc.io/qr"
)

// Two-factor sign-in with an authenticator app (RFC 6238 TOTP: SHA-1,
// 6 digits, 30 s steps), which is what Aegis, 2FAS, Google Authenticator,
// Bitwarden, 1Password and friends expect.

const totpPeriod = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func totpCode(secret string, step int64) string {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpMatch returns the matching time step (allowing one step of clock
// drift either way) or 0.
func totpMatch(secret, code string, now time.Time) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0
	}
	cur := now.Unix() / totpPeriod
	for _, st := range []int64{cur, cur - 1, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, st)), []byte(code)) == 1 {
			return st
		}
	}
	return 0
}

func newRecoveryCodes(n int) (plain, hashes []string) {
	for i := 0; i < n; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		c := strings.ToLower(b32.EncodeToString(b))[:10]
		c = c[:5] + "-" + c[5:]
		plain = append(plain, c)
		hashes = append(hashes, hashToken(c))
	}
	return
}

func normRecovery(code string) string {
	c := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	if len(c) == 10 && !strings.Contains(c, "-") {
		c = c[:5] + "-" + c[5:]
	}
	return c
}

// checkSecondFactor validates a TOTP code or a recovery code for a user with
// 2FA enabled, consuming it so it can't be replayed.
func (s *Server) checkSecondFactor(r *http.Request, userID int64, secret, code string) bool {
	if st := totpMatch(secret, code, time.Now()); st != 0 {
		return s.st.UseTOTPStep(r.Context(), userID, st)
	}
	if c := normRecovery(code); len(c) == 11 {
		if s.st.UseRecoveryCode(r.Context(), userID, hashToken(c)) {
			s.st.Audit(r.Context(), actor(r), clientIP(r), "2fa_recovery_code_used", "")
			return true
		}
	}
	return false
}

// GET /api/me/2fa
func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	t, _ := s.st.GetTOTP(r.Context(), u.ID)
	resp := map[string]any{"enabled": t != nil && t.Enabled, "recovery_left": 0}
	if t != nil && t.Enabled {
		resp["recovery_left"] = len(t.Recovery)
	}
	writeJSON(w, 200, resp)
}

// POST /api/me/2fa/setup {password} -> secret + QR code (not active yet)
func (s *Server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !s.lim.allow("2fa:"+u.Username, 10, 10*time.Minute) {
		writeErr(w, 429, "too many attempts")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(body.Password)) != nil {
		writeErr(w, 400, "password is wrong")
		return
	}
	if t, _ := s.st.GetTOTP(r.Context(), u.ID); t != nil && t.Enabled {
		writeErr(w, 400, "two-factor sign-in is already on; turn it off first")
		return
	}
	secret := newTOTPSecret()
	if err := s.st.SetPendingTOTP(r.Context(), u.ID, secret); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	issuer := "Docker Scout Scanner"
	uri := (&url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + u.Username,
		RawQuery: url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode(),
	}).String()
	resp := map[string]any{"secret": secret, "uri": uri}
	if code, err := qr.Encode(uri, qr.M); err == nil {
		code.Scale = 6
		resp["qr"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	writeJSON(w, 200, resp)
}

// POST /api/me/2fa/enable {code} -> recovery codes
func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !s.lim.allow("2fa:"+u.Username, 10, 10*time.Minute) {
		writeErr(w, 429, "too many attempts")
		return
	}
	t, _ := s.st.GetTOTP(r.Context(), u.ID)
	if t == nil || t.Enabled {
		writeErr(w, 400, "start the setup first")
		return
	}
	st := totpMatch(t.Secret, body.Code, time.Now())
	if st == 0 {
		writeErr(w, 400, "that code doesn't match; check the time on your phone and try the next code")
		return
	}
	plain, hashes := newRecoveryCodes(10)
	if err := s.st.EnableTOTP(r.Context(), u.ID, st, hashes); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if se := currentSession(r); se != nil {
		s.st.DeleteUserSessions(r.Context(), u.ID, se.TokenHash)
	}
	s.audit(r, "2fa_enabled", u.Username)
	writeJSON(w, 200, map[string]any{"ok": true, "recovery_codes": plain})
}

// POST /api/me/2fa/disable {password, code}
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !s.lim.allow("2fa:"+u.Username, 10, 10*time.Minute) {
		writeErr(w, 429, "too many attempts")
		return
	}
	t, _ := s.st.GetTOTP(r.Context(), u.ID)
	if t == nil || !t.Enabled {
		_ = s.st.DeleteTOTP(r.Context(), u.ID)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(body.Password)) != nil || !s.checkSecondFactor(r, u.ID, t.Secret, body.Code) {
		writeErr(w, 400, "password or code is wrong")
		return
	}
	_ = s.st.DeleteTOTP(r.Context(), u.ID)
	s.audit(r, "2fa_disabled", u.Username)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
