// Package notify posts short alerts to a webhook (generic JSON, Slack,
// Discord or ntfy) when a scan finds something new and important.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

var client = &http.Client{Timeout: 15 * time.Second}

type Alert struct {
	Image    string           `json:"image"`
	ImageID  string           `json:"image_id"`
	InUse    bool             `json:"in_use"`
	Findings []*store.Finding `json:"findings"`
}

func (a Alert) Text() string {
	var b strings.Builder
	use := ""
	if a.InUse {
		use = " (running)"
	}
	fmt.Fprintf(&b, "%d new important finding(s) in %s%s\n", len(a.Findings), a.Image, use)
	for i, f := range a.Findings {
		if i == 10 {
			fmt.Fprintf(&b, "…and %d more\n", len(a.Findings)-10)
			break
		}
		tags := []string{f.Severity}
		if f.KEV {
			tags = append(tags, "KEV")
		}
		if f.EPSS >= 0.01 {
			tags = append(tags, fmt.Sprintf("EPSS %.0f%%", f.EPSS*100))
		}
		fix := "no fix yet"
		if f.FixedVersion != "" {
			fix = "fix: " + f.FixedVersion
		}
		fmt.Fprintf(&b, "• %s [%s] %s %s (%s)\n", f.VulnID, strings.Join(tags, ", "), f.PkgName, f.PkgVersion, fix)
	}
	return b.String()
}

func Send(ctx context.Context, url, format string, a Alert) error {
	if url == "" {
		return nil
	}
	text := a.Text()
	var body []byte
	ctype := "application/json"
	switch format {
	case "slack":
		body, _ = json.Marshal(map[string]string{"text": text})
	case "discord":
		if len(text) > 1900 {
			text = text[:1900] + "…"
		}
		body, _ = json.Marshal(map[string]string{"content": text})
	case "ntfy":
		body, ctype = []byte(text), "text/plain"
	default:
		type slim struct {
			ID, Pkg, Version, Fixed, Severity string
			EPSS                              float64
			KEV                               bool
			Risk                              float64
		}
		fs := make([]slim, 0, len(a.Findings))
		for _, f := range a.Findings {
			fs = append(fs, slim{f.VulnID, f.PkgName, f.PkgVersion, f.FixedVersion, f.Severity, f.EPSS, f.KEV, f.Risk})
		}
		body, _ = json.Marshal(map[string]any{"event": "new_findings", "image": a.Image, "image_id": a.ImageID, "in_use": a.InUse, "text": text, "findings": fs})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "docker-scout-scanner")
	if format == "ntfy" {
		req.Header.Set("Title", "Docker scanner: "+a.Image)
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "warning")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
