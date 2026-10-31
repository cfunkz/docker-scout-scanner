// Package api exposes two HTTP listeners: the dashboard API (read-only data
// plus the caller's own password) and the admin API (everything that changes
// state). nginx publishes them on separate ports so the admin side can be
// bound to localhost only.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/analysis"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/config"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/engine"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/scanner"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

type Server struct {
	st      *store.Store
	cfg     *config.Manager
	sc      *scanner.Scanner
	eng     *engine.Runner
	env     config.Env
	log     *slog.Logger
	lim     *limiter
	started time.Time
}

func New(st *store.Store, cfg *config.Manager, sc *scanner.Scanner, eng *engine.Runner, env config.Env, log *slog.Logger) *Server {
	return &Server{st: st, cfg: cfg, sc: sc, eng: eng, env: env, log: log, lim: newLimiter(), started: time.Now()}
}

// readRoutes are shared by both listeners.
func (s *Server) readRoutes(mux *http.ServeMux, scope string) {
	v := func(h http.HandlerFunc) http.HandlerFunc { return s.auth(scope, "viewer", h) }
	mux.HandleFunc("GET /api/overview", v(s.handleOverview))
	mux.HandleFunc("GET /api/images", v(s.handleImages))
	mux.HandleFunc("GET /api/images/{id}", v(s.handleImage))
	mux.HandleFunc("GET /api/images/{id}/findings", v(s.handleFindings))
	mux.HandleFunc("GET /api/images/{id}/diff", v(s.handleDiff))
	mux.HandleFunc("GET /api/images/{id}/fixplan", v(s.handleFixPlan))
	mux.HandleFunc("GET /api/images/{id}/export", v(s.handleExport))
	mux.HandleFunc("GET /api/vulns", v(s.handleVulns))
	mux.HandleFunc("GET /api/vulns/{id}", v(s.handleVuln))
	mux.HandleFunc("GET /api/trend", v(s.handleTrend))
	mux.HandleFunc("GET /api/settings/public", v(s.handlePublicSettings))
	mux.HandleFunc("GET /api/ignores", v(s.handleListIgnores))
	mux.HandleFunc("GET /api/vex", v(s.handleVEX))

	mux.HandleFunc("POST /api/auth/login", s.handleLogin(scope))
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout(scope))
	mux.HandleFunc("GET /api/me", s.handleMe(scope))
	mux.HandleFunc("POST /api/me/password", s.auth(scope, "viewer", s.handleChangePassword))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
}

func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	s.readRoutes(mux, "dashboard")
	return s.middleware(mux)
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	s.readRoutes(mux, "admin")
	a := func(h http.HandlerFunc) http.HandlerFunc { return s.auth("admin", "admin", h) }
	mux.HandleFunc("GET /api/admin/status", a(s.handleStatus))
	mux.HandleFunc("GET /api/admin/jobs", a(s.handleJobs))
	mux.HandleFunc("POST /api/admin/scan", a(s.handleScan))
	mux.HandleFunc("POST /api/admin/sync", a(s.handleSync))
	mux.HandleFunc("POST /api/admin/db/update", a(s.handleDBUpdate))
	mux.HandleFunc("POST /api/admin/intel/update", a(s.handleIntelUpdate))
	mux.HandleFunc("GET /api/admin/settings", a(s.handleGetSettings))
	mux.HandleFunc("PUT /api/admin/settings", a(s.handlePutSettings))
	mux.HandleFunc("POST /api/admin/ignores", a(s.handleAddIgnore))
	mux.HandleFunc("DELETE /api/admin/ignores/{id}", a(s.handleDeleteIgnore))
	mux.HandleFunc("GET /api/admin/users", a(s.handleUsers))
	mux.HandleFunc("POST /api/admin/users", a(s.handleCreateUser))
	mux.HandleFunc("PATCH /api/admin/users/{id}", a(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/admin/users/{id}", a(s.handleDeleteUser))
	mux.HandleFunc("GET /api/admin/sessions", a(s.handleSessions))
	mux.HandleFunc("DELETE /api/admin/sessions/{id}", a(s.handleRevokeSession))
	mux.HandleFunc("GET /api/admin/audit", a(s.handleAudit))
	mux.HandleFunc("POST /api/admin/notify/test", a(s.handleNotifyTest))
	mux.HandleFunc("POST /api/admin/purge", a(s.handlePurge))
	mux.HandleFunc("GET /metrics", s.metricsAuth(a(s.handleMetrics)))
	return s.middleware(mux)
}

// metricsAuth lets Prometheus scrape with a bearer token (METRICS_TOKEN);
// without a token the endpoint falls back to an admin session.
func (s *Server) metricsAuth(withSession http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := os.Getenv("METRICS_TOKEN"); tok != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
				s.handleMetrics(w, r)
				return
			}
		}
		withSession(w, r)
	}
}

var (
	jsonMarshal   = json.Marshal
	jsonUnmarshal = json.Unmarshal
)

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec, "stack", string(debug.Stack()))
				writeErr(w, 500, "internal error")
			}
		}()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

func qInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func (s *Server) image(w http.ResponseWriter, r *http.Request) *store.Image {
	id := r.PathValue("id")
	if !strings.HasPrefix(id, "sha256:") && len(id) == 64 {
		id = "sha256:" + id
	}
	im, err := s.st.GetImage(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return nil
	}
	if im == nil {
		writeErr(w, 404, "image not found")
		return nil
	}
	return im
}

// ---------- read handlers ----------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ims, err := s.st.ListImages(ctx, false)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type top struct {
		ID    string  `json:"id"`
		Name  string  `json:"name"`
		InUse bool    `json:"in_use"`
		Risk  float64 `json:"risk"`
		Crit  int     `json:"critical"`
		High  int     `json:"high"`
		KEV   int     `json:"kev"`
		New   int     `json:"new"`
		EOSL  bool    `json:"eosl"`
	}
	var o struct {
		Images, Scanned, InUse, EOSL, Critical, High, Medium, Low, Unknown, Fixable, KEV, Secrets, NewFindings, Failed int
		LastScan                                                                                                       int64
		TopImages                                                                                                      []top `json:"top_images"`
		Queue                                                                                                          int   `json:"queue"`
		Running                                                                                                        int   `json:"running"`
		DockerOK                                                                                                       bool  `json:"docker_ok"`
	}
	tops := []top{}
	for _, im := range ims {
		if im.Excluded {
			continue
		}
		o.Images++
		inUse := len(im.Containers) > 0
		if inUse {
			o.InUse++
		}
		if im.EOSL {
			o.EOSL++
		}
		sc := im.Scan
		if sc == nil {
			continue
		}
		if sc.Status == "failed" {
			o.Failed++
		}
		o.Scanned++
		o.Critical += sc.Critical
		o.High += sc.High
		o.Medium += sc.Medium
		o.Low += sc.Low
		o.Unknown += sc.Unknown
		o.Fixable += sc.Fixable
		o.KEV += sc.KEV
		o.Secrets += sc.Secrets
		o.NewFindings += sc.NewCount
		o.LastScan = max(o.LastScan, sc.FinishedAt)
		tops = append(tops, top{im.ID, im.Name(), inUse, sc.RiskMax, sc.Critical, sc.High, sc.KEV, sc.NewCount, im.EOSL})
	}
	sort.Slice(tops, func(i, j int) bool {
		if tops[i].Risk != tops[j].Risk {
			return tops[i].Risk > tops[j].Risk
		}
		return tops[i].Crit > tops[j].Crit
	})
	if len(tops) > 8 {
		tops = tops[:8]
	}
	o.TopImages = tops
	o.Queue, o.Running = s.sc.QueueStats()
	o.DockerOK, _ = s.sc.DockerStatus()
	vulns, _ := s.st.FleetVulns(ctx, "", 8)
	writeJSON(w, 200, map[string]any{
		"images": o.Images, "scanned": o.Scanned, "in_use": o.InUse, "eosl": o.EOSL, "failed": o.Failed,
		"critical": o.Critical, "high": o.High, "medium": o.Medium, "low": o.Low, "unknown": o.Unknown,
		"fixable": o.Fixable, "kev": o.KEV, "secrets": o.Secrets, "new_findings": o.NewFindings,
		"last_scan": o.LastScan, "top_images": o.TopImages, "top_vulns": vulns,
		"queue": o.Queue, "running": o.Running, "docker_ok": o.DockerOK,
	})
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	ims, err := s.st.ListImages(r.Context(), r.URL.Query().Get("all") == "1")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if ims == nil {
		ims = []*store.Image{}
	}
	writeJSON(w, 200, ims)
}

func (s *Server) handleImage(w http.ResponseWriter, r *http.Request) {
	im := s.image(w, r)
	if im == nil {
		return
	}
	ref := ""
	if len(im.RepoTags) > 0 {
		ref = im.RepoTags[0]
	}
	hist, _ := s.st.ScanHistory(r.Context(), im.ID, ref, 30)
	writeJSON(w, 200, map[string]any{"image": im, "history": hist, "has_sbom": im.SBOMPath != ""})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	im := s.image(w, r)
	if im == nil {
		return
	}
	scanID := int64(qInt(r, "scan", int(im.LatestScan)))
	if scanID == 0 {
		writeJSON(w, 200, []any{})
		return
	}
	sc, _ := s.st.GetScan(r.Context(), scanID)
	if sc == nil {
		writeErr(w, 404, "scan not found")
		return
	}
	fs, err := s.st.Findings(r.Context(), scanID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, fs)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	im := s.image(w, r)
	if im == nil {
		return
	}
	if im.Scan == nil || im.Scan.PrevScan == 0 {
		writeJSON(w, 200, map[string]any{"new": []any{}, "resolved": []any{}, "baseline": nil})
		return
	}
	cur, _ := s.st.Findings(r.Context(), im.Scan.ID)
	prev, _ := s.st.Findings(r.Context(), im.Scan.PrevScan)
	base, _ := s.st.GetScan(r.Context(), im.Scan.PrevScan)
	d := analysis.DiffFindings(prev, cur)
	writeJSON(w, 200, map[string]any{"new": d.New, "resolved": d.Resolved, "baseline": base})
}

func (s *Server) handleFixPlan(w http.ResponseWriter, r *http.Request) {
	im := s.image(w, r)
	if im == nil {
		return
	}
	if im.LatestScan == 0 {
		writeJSON(w, 200, analysis.FixPlan{Steps: []*analysis.FixStep{}})
		return
	}
	fs, err := s.st.Findings(r.Context(), im.LatestScan)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, analysis.BuildFixPlan(fs, im))
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	vs, err := s.st.FleetVulns(r.Context(), r.URL.Query().Get("q"), min(max(qInt(r, "limit", 500), 1), 5000))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, vs)
}

func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	f, imgs, err := s.st.VulnDetail(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "not found in any current image")
		return
	}
	writeJSON(w, 200, map[string]any{"vuln": f, "images": imgs})
}

func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.Trend(r.Context(), min(max(qInt(r, "days", 90), 1), 730))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, t)
}

func (s *Server) handlePublicSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.Get().Public())
}

func (s *Server) handleListIgnores(w http.ResponseWriter, r *http.Request) {
	rs, err := s.st.IgnoreRules(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}
