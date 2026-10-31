// Package config holds runtime settings. Settings live in the database so the
// admin panel can change them without a restart; environment variables only
// provide first-boot defaults and paths.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

// Env is the static process configuration (paths, listeners).
type Env struct {
	DataDir      string
	CertDir      string
	PublicAddr   string
	AdminAddr    string
	DockerHost   string
	TrivyBin     string
	GrypeBin     string
	TLSSANs      []string
	SecureCookie bool
}

func LoadEnv() Env {
	e := Env{
		DataDir:      getenv("DATA_DIR", "/data"),
		CertDir:      getenv("CERT_DIR", "/certs"),
		PublicAddr:   getenv("PUBLIC_ADDR", ":8000"),
		AdminAddr:    getenv("ADMIN_ADDR", ":8001"),
		DockerHost:   getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
		TrivyBin:     getenv("TRIVY_BIN", "trivy"),
		GrypeBin:     getenv("GRYPE_BIN", "grype"),
		SecureCookie: getenv("INSECURE_COOKIES", "") == "",
	}
	for _, s := range strings.Split(getenv("TLS_SANS", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			e.TLSSANs = append(e.TLSSANs, s)
		}
	}
	return e
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// Settings are the admin-editable knobs.
type Settings struct {
	// Scanning
	Engine         string   `json:"engine"`           // trivy|grype|both
	Concurrency    int      `json:"concurrency"`      // parallel image scans
	ScanIntervalH  int      `json:"scan_interval_h"`  // full rescan cadence, 0 = off
	WatchEvents    bool     `json:"watch_events"`     // scan new images as soon as they appear
	ScanOnStart    bool     `json:"scan_on_start"`    // scan unscanned images at boot
	OnlyInUse      bool     `json:"only_in_use"`      // only scan images backing containers
	Exclude        []string `json:"exclude"`          // glob patterns of repo:tag to skip
	SecretScanning bool     `json:"secret_scanning"`  // look for secrets baked into layers
	ScanTimeoutMin int      `json:"scan_timeout_min"` // per image
	DBUpdateH      int      `json:"db_update_h"`      // vuln DB refresh cadence
	Offline        bool     `json:"offline"`          // never touch the network
	HistoryKeep    int      `json:"history_keep"`     // scans per image with full findings
	// Threat intel
	EPSSEnabled bool   `json:"epss_enabled"`
	KEVEnabled  bool   `json:"kev_enabled"`
	EPSSURL     string `json:"epss_url"`
	KEVURL      string `json:"kev_url"`
	// Notifications
	WebhookURL       string   `json:"webhook_url"`
	WebhookFormat    string   `json:"webhook_format"` // generic|slack|discord|ntfy
	NotifySeverities []string `json:"notify_severities"`
	NotifyKEV        bool     `json:"notify_kev"`
	NotifyMinEPSS    float64  `json:"notify_min_epss"` // 0..1, 0 = off
	// Access
	SessionHours    int  `json:"session_hours"`
	RequireLogin    bool `json:"require_login"`
	LockoutAttempts int  `json:"lockout_attempts"`
	LockoutMinutes  int  `json:"lockout_minutes"`
}

func Defaults() Settings {
	return Settings{
		Engine:           getenv("DEFAULT_ENGINE", "trivy"),
		Concurrency:      2,
		ScanIntervalH:    24,
		WatchEvents:      true,
		ScanOnStart:      true,
		Exclude:          []string{},
		ScanTimeoutMin:   15,
		DBUpdateH:        12,
		Offline:          getenv("OFFLINE", "") != "",
		HistoryKeep:      10,
		EPSSEnabled:      true,
		KEVEnabled:       true,
		EPSSURL:          "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		KEVURL:           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		WebhookFormat:    "generic",
		NotifySeverities: []string{"CRITICAL"},
		NotifyKEV:        true,
		SessionHours:     12,
		RequireLogin:     true,
		LockoutAttempts:  5,
		LockoutMinutes:   15,
	}
}

func (s *Settings) Validate() error {
	switch s.Engine {
	case "trivy", "grype", "both":
	default:
		return fmt.Errorf("engine must be trivy, grype or both")
	}
	if s.Concurrency < 1 || s.Concurrency > 16 {
		return fmt.Errorf("concurrency must be 1..16")
	}
	if s.ScanIntervalH < 0 || s.ScanIntervalH > 24*30 {
		return fmt.Errorf("scan interval must be 0..720 hours")
	}
	if s.DBUpdateH < 1 || s.DBUpdateH > 24*7 {
		return fmt.Errorf("DB update interval must be 1..168 hours")
	}
	if s.ScanTimeoutMin < 1 || s.ScanTimeoutMin > 240 {
		return fmt.Errorf("scan timeout must be 1..240 minutes")
	}
	if s.HistoryKeep < 1 || s.HistoryKeep > 1000 {
		return fmt.Errorf("history must be 1..1000")
	}
	if s.SessionHours < 1 || s.SessionHours > 24*30 {
		return fmt.Errorf("session lifetime must be 1..720 hours")
	}
	if s.LockoutAttempts < 1 || s.LockoutAttempts > 100 || s.LockoutMinutes < 1 || s.LockoutMinutes > 1440 {
		return fmt.Errorf("lockout values out of range")
	}
	if s.NotifyMinEPSS < 0 || s.NotifyMinEPSS > 1 {
		return fmt.Errorf("EPSS threshold must be between 0 and 1")
	}
	switch s.WebhookFormat {
	case "generic", "slack", "discord", "ntfy":
	default:
		return fmt.Errorf("webhook format must be generic, slack, discord or ntfy")
	}
	for _, u := range []string{s.WebhookURL, s.EPSSURL, s.KEVURL} {
		if u == "" {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("invalid URL %q", u)
		}
	}
	for _, sv := range s.NotifySeverities {
		switch sv {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		default:
			return fmt.Errorf("unknown severity %q", sv)
		}
	}
	clean := []string{}
	for _, p := range s.Exclude {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, "x"); err != nil {
			return fmt.Errorf("bad exclude pattern %q", p)
		}
		clean = append(clean, p)
	}
	s.Exclude = clean
	return nil
}

// Manager caches settings in memory and persists them to the store.
type Manager struct {
	st   *store.Store
	mu   sync.RWMutex
	cur  Settings
	subs []func(Settings)
}

func NewManager(ctx context.Context, st *store.Store) (*Manager, error) {
	m := &Manager{st: st, cur: Defaults()}
	if raw, ok := st.GetSetting(ctx, "settings"); ok {
		// Unmarshal over defaults so new fields get sane values after upgrades.
		if err := json.Unmarshal([]byte(raw), &m.cur); err != nil {
			return nil, fmt.Errorf("corrupt settings: %w", err)
		}
	}
	if v := os.Getenv("OFFLINE"); v != "" {
		m.cur.Offline, _ = strconv.ParseBool(v)
	}
	return m, nil
}

func (m *Manager) Get() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.cur
	s.Exclude = append([]string(nil), m.cur.Exclude...)
	s.NotifySeverities = append([]string(nil), m.cur.NotifySeverities...)
	return s
}

func (m *Manager) Set(ctx context.Context, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	if err := m.st.SetSetting(ctx, "settings", string(b)); err != nil {
		return err
	}
	m.mu.Lock()
	m.cur = s
	subs := append([]func(Settings){}, m.subs...)
	m.mu.Unlock()
	for _, f := range subs {
		f(s)
	}
	return nil
}

// OnChange registers a callback run after settings are saved.
func (m *Manager) OnChange(f func(Settings)) {
	m.mu.Lock()
	m.subs = append(m.subs, f)
	m.mu.Unlock()
}

// Public returns settings safe to show to every logged-in user (no secrets).
func (s Settings) Public() map[string]any {
	return map[string]any{
		"engine":           s.Engine,
		"scan_interval_h":  s.ScanIntervalH,
		"watch_events":     s.WatchEvents,
		"only_in_use":      s.OnlyInUse,
		"secret_scanning":  s.SecretScanning,
		"offline":          s.Offline,
		"epss_enabled":     s.EPSSEnabled,
		"kev_enabled":      s.KEVEnabled,
		"history_keep":     s.HistoryKeep,
		"notifications_on": s.WebhookURL != "",
		"session_hours":    s.SessionHours,
	}
}

// Redacted hides the webhook URL (it frequently embeds a token).
func (s Settings) Redacted() Settings {
	if s.WebhookURL != "" {
		if u, err := url.Parse(s.WebhookURL); err == nil {
			s.WebhookURL = u.Scheme + "://" + u.Host + "/…"
		}
	}
	return s
}
