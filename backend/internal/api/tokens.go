package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

// API tokens let scripts, Home Assistant, Homepage widgets and CI read the
// scanner's data without a browser session.
//
//   Authorization: Bearer dss_...
//
// A token acts as the user who created it, capped by its scope:
//   read  - GET requests on either port
//   admin - everything, but only on the admin port (localhost) and only
//           while the owner is still an admin
// Tokens can't change passwords, 2FA or other tokens.

const tokenPrefix = "dss_"

func (s *Server) tokenAuth(scope, role string, h http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	ip := clientIP(r)
	deny := func(code int, msg string) {
		s.lim.allow("tokfail:"+ip, 1000, time.Minute) // record the failure
		writeErr(w, code, msg)
	}
	if !s.lim.allow("tok:"+ip, 600, time.Minute) {
		writeErr(w, 429, "too many requests")
		return
	}
	if len(raw) > 100 || !strings.HasPrefix(raw, tokenPrefix) {
		deny(401, "invalid API token")
		return
	}
	t, err := s.st.APITokenByHash(r.Context(), hashToken(raw))
	if err != nil || t == nil || (t.ExpiresAt != 0 && t.ExpiresAt < time.Now().Unix()) {
		deny(401, "invalid or expired API token")
		return
	}
	u, _ := s.st.UserByID(r.Context(), t.UserID)
	if u == nil || u.MustChange {
		deny(401, "token owner can't sign in")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/me") {
		deny(403, "API tokens can't manage accounts")
		return
	}
	readOnly := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case t.Scope == "admin" && scope == "admin" && u.Role == "admin":
		// full access on the admin listener
	case readOnly && role == "viewer":
		// read access anywhere
	default:
		deny(403, "this token's scope doesn't allow that")
		return
	}
	if time.Now().Unix()-t.LastUsed > 60 {
		s.st.TouchAPIToken(r.Context(), t.ID, ip)
	}
	ctx := context.WithValue(r.Context(), ctxUser, u)
	h(w, r.WithContext(ctx))
}

type tokenOut struct {
	*store.APIToken
	Expired bool `json:"expired"`
}

func wrapTokens(ts []*store.APIToken) []tokenOut {
	now := time.Now().Unix()
	out := make([]tokenOut, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenOut{t, t.ExpiresAt != 0 && t.ExpiresAt < now})
	}
	return out
}

// GET /api/me/tokens
func (s *Server) handleMyTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.st.APITokens(r.Context(), currentUser(r).ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, wrapTokens(ts))
}

// POST /api/me/tokens {name, scope, days}
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var body struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
		Days  int    `json:"days"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 64 {
		writeErr(w, 400, "give the token a name (up to 64 characters)")
		return
	}
	if body.Scope == "" {
		body.Scope = "read"
	}
	if body.Scope != "read" && body.Scope != "admin" {
		writeErr(w, 400, "scope must be read or admin")
		return
	}
	if body.Scope == "admin" && u.Role != "admin" {
		writeErr(w, 403, "only admins can create admin tokens")
		return
	}
	if body.Days < 0 || body.Days > 3650 {
		writeErr(w, 400, "expiry must be 0 (never) to 3650 days")
		return
	}
	if ts, _ := s.st.APITokens(r.Context(), u.ID); len(ts) >= 50 {
		writeErr(w, 400, "too many tokens; delete some first")
		return
	}
	raw := tokenPrefix + randToken(30)
	t := &store.APIToken{UserID: u.ID, Name: body.Name, TokenHash: hashToken(raw), Prefix: raw[:len(tokenPrefix)+6], Scope: body.Scope}
	if body.Days > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(body.Days) * 24 * time.Hour).Unix()
	}
	id, err := s.st.CreateAPIToken(r.Context(), t)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, "token_created", body.Name+" ("+body.Scope+")")
	writeJSON(w, 200, map[string]any{"id": id, "token": raw})
}

// DELETE /api/me/tokens/{id}
func (s *Server) handleDeleteMyToken(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ok, err := s.st.DeleteAPIToken(r.Context(), id, currentUser(r).ID)
	if err != nil || !ok {
		writeErr(w, 404, "no such token")
		return
	}
	s.audit(r, "token_deleted", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/admin/tokens (everyone's)
func (s *Server) handleAllTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.st.APITokens(r.Context(), 0)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, wrapTokens(ts))
}

// DELETE /api/admin/tokens/{id}
func (s *Server) handleAdminDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ok, err := s.st.DeleteAPIToken(r.Context(), id, 0)
	if err != nil || !ok {
		writeErr(w, 404, "no such token")
		return
	}
	s.audit(r, "token_revoked", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]bool{"ok": true})
}
