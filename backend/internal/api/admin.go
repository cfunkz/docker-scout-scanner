package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/config"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/notify"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

func (s *Server) audit(r *http.Request, action, detail string) {
	s.st.Audit(r.Context(), actor(r), clientIP(r), action, detail)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	kev, epss := s.st.IntelCounts(ctx)
	q, run := s.sc.QueueStats()
	dok, derr := s.sc.DockerStatus()
	var dbSize int64
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(s.env.DataDir + "/scanner.db" + suffix); err == nil {
			dbSize += fi.Size()
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	writeJSON(w, 200, map[string]any{
		"trivy":       s.eng.TrivyStatus(ctx),
		"grype":       s.eng.GrypeStatus(ctx),
		"kev_entries": kev, "epss_entries": epss,
		"tasks": s.sc.Tasks(),
		"queue": q, "running": run,
		"docker_ok": dok, "docker_error": derr,
		"version":                  Version,
		"uptime_s":                 int64(time.Since(s.started).Seconds()),
		"db_bytes":                 dbSize,
		"heap_bytes":               m.HeapAlloc,
		"go":                       runtime.Version(),
		"initial_password_pending": fileExists(s.env.DataDir + "/initial-admin-password"),
	})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.sc.Jobs())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ImageID string `json:"image_id"`
		All     bool   `json:"all"`
		Force   bool   `json:"force"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.All {
		_ = s.sc.Sync(r.Context())
		n, err := s.sc.ScanAll(r.Context(), "manual", body.Force)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		s.audit(r, "scan_all", fmt.Sprintf("queued=%d force=%v", n, body.Force))
		writeJSON(w, 200, map[string]int{"queued": n})
		return
	}
	im, err := s.st.GetImage(r.Context(), body.ImageID)
	if err != nil || im == nil || !im.Present {
		writeErr(w, 404, "image not found on this host")
		return
	}
	j, _ := s.sc.Enqueue(im.ID, im.Name(), "manual", body.Force)
	s.audit(r, "scan", im.Name())
	writeJSON(w, 200, j)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if err := s.sc.Sync(r.Context()); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleDBUpdate(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "db_update", "")
	go func() {
		if err := s.sc.UpdateDBs(context.Background()); err != nil {
			s.log.Warn("manual DB update failed", "err", err)
		}
	}()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func (s *Server) handleIntelUpdate(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "intel_update", "")
	go func() {
		ctx := context.Background()
		_ = s.sc.RefreshIntel(ctx, "kev")
		_ = s.sc.RefreshIntel(ctx, "epss")
		_, _ = s.sc.ScanAll(ctx, "intel-update", false)
	}()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.Get().Redacted())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	cur := s.cfg.Get()
	next := cur
	if !readJSON(w, r, &next) {
		return
	}
	// The UI shows a redacted webhook URL; sending it back unchanged keeps the real one.
	if next.WebhookURL == cur.Redacted().WebhookURL {
		next.WebhookURL = cur.WebhookURL
	}
	if err := s.cfg.Set(r.Context(), next); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "settings_changed", diffSettings(cur, next))
	writeJSON(w, 200, s.cfg.Get().Redacted())
}

func diffSettings(a, b config.Settings) string {
	am, bm := structMap(a.Redacted()), structMap(b.Redacted())
	var out []string
	for k, v := range bm {
		if fmt.Sprint(am[k]) != fmt.Sprint(v) {
			out = append(out, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(out, " ")
}

func structMap(v any) map[string]any {
	var m map[string]any
	b, _ := jsonMarshal(v)
	_ = jsonUnmarshal(b, &m)
	return m
}

// ---------- ignore rules ----------

var vulnIDRe = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._:-]{2,80})$`)

func (s *Server) handleAddIgnore(w http.ResponseWriter, r *http.Request) {
	var ru store.IgnoreRule
	if !readJSON(w, r, &ru) {
		return
	}
	ru.VulnID = strings.TrimSpace(ru.VulnID)
	if !vulnIDRe.MatchString(ru.VulnID) {
		writeErr(w, 400, "vulnerability id looks wrong (use e.g. CVE-2024-1234 or *)")
		return
	}
	if ru.Pkg == "" {
		ru.Pkg = "*"
	}
	if ru.Image == "" {
		ru.Image = "*"
	}
	if ru.VulnID == "*" && ru.Pkg == "*" && ru.Image == "*" {
		writeErr(w, 400, "a rule must narrow down at least one of vulnerability, package or image")
		return
	}
	if len(ru.Pkg) > 200 || len(ru.Image) > 300 || len(ru.Reason) > 1000 {
		writeErr(w, 400, "field too long")
		return
	}
	if strings.TrimSpace(ru.Reason) == "" {
		writeErr(w, 400, "a reason is required, so the decision can be reviewed later")
		return
	}
	switch ru.Status {
	case "", "not_affected":
		ru.Status = "not_affected"
	case "affected", "fixed", "under_investigation":
	default:
		writeErr(w, 400, "status must be an OpenVEX status")
		return
	}
	ru.CreatedBy = actor(r)
	id, err := s.st.AddIgnoreRule(r.Context(), &ru)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, "ignore_added", fmt.Sprintf("%s pkg=%s image=%s", ru.VulnID, ru.Pkg, ru.Image))
	// Re-match so counts reflect the rule right away (SBOMs make this cheap).
	go s.sc.ScanAll(context.Background(), "rule-change", false)
	writeJSON(w, 200, map[string]int64{"id": id})
}

func (s *Server) handleDeleteIgnore(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.st.DeleteIgnoreRule(r.Context(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, "ignore_deleted", strconv.FormatInt(id, 10))
	go s.sc.ScanAll(context.Background(), "rule-change", false)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------- users & sessions ----------

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{3,64}$`)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.st.Users(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tf := s.st.TOTPEnabled(r.Context())
	type userOut struct {
		*store.User
		TwoFactor bool `json:"two_factor"`
	}
	out := make([]userOut, 0, len(us))
	for _, u := range us {
		out = append(out, userOut{u, tf[u.ID]})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !usernameRe.MatchString(body.Username) {
		writeErr(w, 400, "username: 3-64 chars of letters, digits, . _ @ -")
		return
	}
	if body.Role != "admin" && body.Role != "viewer" {
		writeErr(w, 400, "role must be viewer or admin")
		return
	}
	generated := false
	if body.Password == "" {
		body.Password, generated = randToken(15), true
	}
	if err := checkPasswordPolicy(body.Password, body.Username); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	id, err := s.st.CreateUser(r.Context(), body.Username, h, body.Role, true)
	if err != nil {
		writeErr(w, 409, "username already exists")
		return
	}
	s.audit(r, "user_created", body.Username+" role="+body.Role)
	resp := map[string]any{"id": id}
	if generated {
		resp["password"] = body.Password
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, _ := s.st.UserByID(r.Context(), id)
	if u == nil {
		writeErr(w, 404, "no such user")
		return
	}
	var body struct {
		Role          string `json:"role"`
		ResetPassword bool   `json:"reset_password"`
		Unlock        bool   `json:"unlock"`
		Reset2FA      bool   `json:"reset_2fa"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	resp := map[string]any{"ok": true}
	if body.Role != "" && body.Role != u.Role {
		if body.Role != "admin" && body.Role != "viewer" {
			writeErr(w, 400, "role must be viewer or admin")
			return
		}
		if u.Role == "admin" && s.st.AdminCount(r.Context()) <= 1 {
			writeErr(w, 400, "cannot demote the last admin")
			return
		}
		_ = s.st.SetRole(r.Context(), id, body.Role)
		s.st.DeleteUserSessions(r.Context(), id, "")
		s.audit(r, "user_role", u.Username+" -> "+body.Role)
	}
	if body.ResetPassword {
		pw := randToken(15)
		h, _ := HashPassword(pw)
		_ = s.st.SetPassword(r.Context(), id, h, true)
		s.st.DeleteUserSessions(r.Context(), id, "")
		resp["password"] = pw
		s.audit(r, "user_password_reset", u.Username)
	}
	if body.Reset2FA {
		_ = s.st.DeleteTOTP(r.Context(), id)
		s.st.DeleteUserSessions(r.Context(), id, "")
		s.audit(r, "user_2fa_reset", u.Username)
	}
	if body.Unlock {
		s.st.LoginOK(r.Context(), id)
		s.audit(r, "user_unlocked", u.Username)
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, _ := s.st.UserByID(r.Context(), id)
	if u == nil {
		writeErr(w, 404, "no such user")
		return
	}
	if me := currentUser(r); me != nil && me.ID == id {
		writeErr(w, 400, "you cannot delete yourself")
		return
	}
	if u.Role == "admin" && s.st.AdminCount(r.Context()) <= 1 {
		writeErr(w, 400, "cannot delete the last admin")
		return
	}
	_ = s.st.DeleteUser(r.Context(), id)
	s.audit(r, "user_deleted", u.Username)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := s.st.Sessions(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cur := currentSession(r)
	type out struct {
		*store.Session
		Current bool `json:"current"`
	}
	res := []out{}
	for _, se := range ss {
		res = append(res, out{se, cur != nil && se.TokenHash == cur.TokenHash})
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteSessionByPrefix(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "session_revoked", r.PathValue("id"))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.AuditLog(r.Context(), min(max(qInt(r, "limit", 200), 1), 2000))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	if cfg.WebhookURL == "" {
		writeErr(w, 400, "no webhook URL configured")
		return
	}
	alert := notify.Alert{Image: "example/image:latest", ImageID: "sha256:test", InUse: true, Findings: []*store.Finding{{
		VulnID: "CVE-0000-0000", Severity: "CRITICAL", PkgName: "example-lib", PkgVersion: "1.0.0", FixedVersion: "1.0.1", KEV: true, EPSS: 0.42, Risk: 95,
	}}}
	if err := notify.Send(r.Context(), cfg.WebhookURL, cfg.WebhookFormat, alert); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.audit(r, "notify_test", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		What string `json:"what"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	var detail string
	switch body.What {
	case "absent":
		n, err := s.st.DeleteAbsentImages(ctx)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		detail = fmt.Sprintf("%d images removed", n)
	case "history":
		n, err := s.st.PruneHistory(ctx, 1)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		detail = fmt.Sprintf("%d scans pruned", n)
	case "sboms":
		_ = s.st.ClearSBOMs(ctx)
		ents, _ := os.ReadDir(s.eng.SBOMDir)
		for _, e := range ents {
			_ = os.Remove(s.eng.SBOMDir + "/" + e.Name())
		}
		detail = fmt.Sprintf("%d SBOMs removed; next scan re-reads images", len(ents))
	case "vacuum":
		if _, err := s.st.DB.ExecContext(ctx, `VACUUM`); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		detail = "database compacted"
	default:
		writeErr(w, 400, "what must be absent, history, sboms or vacuum")
		return
	}
	s.audit(r, "purge_"+body.What, detail)
	writeJSON(w, 200, map[string]string{"result": detail})
}

// ---------- Prometheus ----------

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ims, err := s.st.ListImages(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	esc := func(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) }
	fmt.Fprintln(w, "# HELP dss_image_vulnerabilities Open vulnerabilities in the latest scan of an image.")
	fmt.Fprintln(w, "# TYPE dss_image_vulnerabilities gauge")
	for _, im := range ims {
		if im.Scan == nil {
			continue
		}
		for _, p := range []struct {
			sev string
			n   int
		}{{"critical", im.Scan.Critical}, {"high", im.Scan.High}, {"medium", im.Scan.Medium}, {"low", im.Scan.Low}, {"unknown", im.Scan.Unknown}} {
			fmt.Fprintf(w, "dss_image_vulnerabilities{image=%q,severity=%q,in_use=\"%v\"} %d\n", esc(im.Name()), p.sev, len(im.Containers) > 0, p.n)
		}
	}
	fmt.Fprintln(w, "# HELP dss_image_kev Vulnerabilities on the CISA KEV list.")
	fmt.Fprintln(w, "# TYPE dss_image_kev gauge")
	for _, im := range ims {
		if im.Scan != nil {
			fmt.Fprintf(w, "dss_image_kev{image=%q} %d\n", esc(im.Name()), im.Scan.KEV)
		}
	}
	fmt.Fprintln(w, "# HELP dss_image_risk_max Highest risk score (0-100) in the image.")
	fmt.Fprintln(w, "# TYPE dss_image_risk_max gauge")
	for _, im := range ims {
		if im.Scan != nil {
			fmt.Fprintf(w, "dss_image_risk_max{image=%q} %.1f\n", esc(im.Name()), im.Scan.RiskMax)
		}
	}
	fmt.Fprintln(w, "# HELP dss_image_last_scan_timestamp_seconds Finish time of the latest scan.")
	fmt.Fprintln(w, "# TYPE dss_image_last_scan_timestamp_seconds gauge")
	for _, im := range ims {
		if im.Scan != nil {
			fmt.Fprintf(w, "dss_image_last_scan_timestamp_seconds{image=%q} %d\n", esc(im.Name()), im.Scan.FinishedAt)
		}
	}
	q, run := s.sc.QueueStats()
	fmt.Fprintf(w, "# TYPE dss_scan_queue gauge\ndss_scan_queue %d\n# TYPE dss_scans_running gauge\ndss_scans_running %d\n", q, run)
}
