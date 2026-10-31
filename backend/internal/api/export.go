package api

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/analysis"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func fileName(im *store.Image, ext string) string {
	n := unsafeName.ReplaceAllString(im.Name(), "_")
	return fmt.Sprintf("%s-%s.%s", strings.Trim(n, "_"), time.Now().Format("20060102"), ext)
}

func attach(w http.ResponseWriter, ctype, name string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
}

// csvSafe neutralises spreadsheet formula injection from untrusted advisory text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	im := s.image(w, r)
	if im == nil {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "sbom" {
		if im.SBOMPath == "" {
			writeErr(w, 404, "no SBOM yet")
			return
		}
		f, err := os.Open(im.SBOMPath)
		if err != nil {
			writeErr(w, 404, "SBOM missing")
			return
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		attach(w, "application/vnd.cyclonedx+json", fileName(im, "cdx.json"))
		_, _ = io.Copy(w, gz)
		return
	}
	if im.LatestScan == 0 {
		writeErr(w, 404, "image not scanned yet")
		return
	}
	fs, err := s.st.Findings(r.Context(), im.LatestScan)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	switch format {
	case "csv":
		attach(w, "text/csv; charset=utf-8", fileName(im, "csv"))
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "severity", "cvss", "epss", "kev", "risk", "package", "installed", "fixed", "type", "path", "layer", "engines", "ignored", "title", "url"})
		for _, f := range fs {
			_ = cw.Write([]string{f.VulnID, f.Severity, fmt.Sprintf("%.1f", f.CVSS), fmt.Sprintf("%.5f", f.EPSS), fmt.Sprint(f.KEV),
				fmt.Sprintf("%.1f", f.Risk), csvSafe(f.PkgName), csvSafe(f.PkgVersion), csvSafe(f.FixedVersion), f.PkgType, csvSafe(f.PkgPath),
				f.Layer, f.Engines, fmt.Sprint(f.IgnoredBy != 0), csvSafe(f.Title), csvSafe(f.URL)})
		}
		cw.Flush()
	case "sarif":
		attach(w, "application/sarif+json", fileName(im, "sarif"))
		writeJSON(w, 200, toSARIF(im, fs))
	default:
		attach(w, "application/json", fileName(im, "json"))
		writeJSON(w, 200, map[string]any{"image": im, "scan": im.Scan, "findings": fs, "fix_plan": analysis.BuildFixPlan(fs, im)})
	}
}

func toSARIF(im *store.Image, fs []*store.Finding) map[string]any {
	level := map[string]string{"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}
	rules := []map[string]any{}
	seen := map[string]bool{}
	results := []map[string]any{}
	for _, f := range fs {
		if f.IgnoredBy != 0 {
			continue
		}
		if !seen[f.VulnID] {
			seen[f.VulnID] = true
			rules = append(rules, map[string]any{
				"id": f.VulnID, "shortDescription": map[string]string{"text": firstNonEmpty(f.Title, f.VulnID)},
				"helpUri": f.URL, "properties": map[string]any{"security-severity": fmt.Sprintf("%.1f", f.CVSS), "tags": []string{"security", "vulnerability"}},
			})
		}
		msg := fmt.Sprintf("%s %s in %s %s", f.Severity, f.VulnID, f.PkgName, f.PkgVersion)
		if f.FixedVersion != "" {
			msg += ", fixed in " + f.FixedVersion
		}
		loc := firstNonEmpty(f.PkgPath, im.Name())
		results = append(results, map[string]any{
			"ruleId": f.VulnID, "level": level[f.Severity], "message": map[string]string{"text": msg},
			"locations": []map[string]any{{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": loc}}}},
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []map[string]any{{"tool": map[string]any{"driver": map[string]any{"name": "docker-scout-scanner", "rules": rules}}, "results": results}},
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// handleVEX exports accepted-risk rules as an OpenVEX document so decisions
// made here can be fed back into Trivy/Grype in CI (`--vex`).
func (s *Server) handleVEX(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.IgnoreRules(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	now := time.Now().Unix()
	stmts := []map[string]any{}
	for _, ru := range rules {
		if ru.VulnID == "*" || (ru.ExpiresAt > 0 && ru.ExpiresAt < now) {
			continue
		}
		st := map[string]any{
			"vulnerability": map[string]string{"name": ru.VulnID},
			"status":        ru.Status,
			"timestamp":     time.Unix(ru.CreatedAt, 0).UTC().Format(time.RFC3339),
		}
		prods := []map[string]any{}
		if ru.Image != "*" && ru.Image != "" {
			p := map[string]any{"@id": "pkg:oci/" + ru.Image}
			if ru.Pkg != "*" && ru.Pkg != "" {
				p["subcomponents"] = []map[string]string{{"@id": ru.Pkg}}
			}
			prods = append(prods, p)
		} else if ru.Pkg != "*" && ru.Pkg != "" {
			prods = append(prods, map[string]any{"@id": ru.Pkg})
		}
		if len(prods) > 0 {
			st["products"] = prods
		}
		if ru.Status == "not_affected" {
			st["justification"] = firstNonEmpty(ru.Justification, "vulnerable_code_not_in_execute_path")
			st["impact_statement"] = ru.Reason
		} else {
			st["status_notes"] = ru.Reason
		}
		stmts = append(stmts, st)
	}
	attach(w, "application/json", "accepted-risk.openvex.json")
	writeJSON(w, 200, map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://openvex.dev/docs/docker-scout-scanner/" + randToken(8),
		"author":     "docker-scout-scanner",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"version":    1,
		"statements": stmts,
	})
}
