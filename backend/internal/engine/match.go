package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

// MatchResult is what one engine run produced.
type MatchResult struct {
	Findings []*store.Finding
	EOSL     bool
	OSFamily string
	OSName   string
}

// ---------- Trivy ----------

type trivyReport struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			VendorIDs        []string `json:"VendorIDs"`
			PkgName          string   `json:"PkgName"`
			PkgPath          string   `json:"PkgPath"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Status           string   `json:"Status"`
			Severity         string   `json:"Severity"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			PrimaryURL       string   `json:"PrimaryURL"`
			PublishedDate    string   `json:"PublishedDate"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			Layer struct {
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
			CVSS map[string]struct {
				V3Score  float64 `json:"V3Score"`
				V40Score float64 `json:"V40Score"`
				V2Score  float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			Layer     struct {
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
		} `json:"Secrets"`
	} `json:"Results"`
}

// MatchTrivy runs `trivy sbom` against a stored SBOM.
func (r *Runner) MatchTrivy(ctx context.Context, sbomGz string, offline bool) (*MatchResult, error) {
	path, cleanup, err := readSBOMTo(sbomGz)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var out bytes.Buffer
	if err := r.run(ctx, offline, &out, r.TrivyBin, "sbom", "--quiet", "--cache-backend", "memory", "--format", "json", "--skip-db-update", "--skip-java-db-update", path); err != nil {
		return nil, err
	}
	return parseTrivy(out.Bytes())
}

func parseTrivy(b []byte) (*MatchResult, error) {
	var rep trivyReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	res := &MatchResult{}
	if rep.Metadata.OS != nil {
		res.EOSL, res.OSFamily, res.OSName = rep.Metadata.OS.EOSL, rep.Metadata.OS.Family, rep.Metadata.OS.Name
	}
	for _, rr := range rep.Results {
		for _, v := range rr.Vulnerabilities {
			f := &store.Finding{
				Kind:         "vuln",
				VulnID:       v.VulnerabilityID,
				Aliases:      strings.Join(v.VendorIDs, ","),
				PkgName:      v.PkgName,
				PkgVersion:   v.InstalledVersion,
				PkgType:      rr.Type,
				PURL:         v.PkgIdentifier.PURL,
				PkgPath:      v.PkgPath,
				FixedVersion: v.FixedVersion,
				Severity:     normSeverity(v.Severity),
				Title:        cleanTitle(v.Title),
				Description:  truncate(v.Description, 1500),
				URL:          v.PrimaryURL,
				Published:    v.PublishedDate,
				Layer:        v.Layer.DiffID,
				Engines:      "trivy",
			}
			if v.Status == "will_not_fix" || v.Status == "end_of_life" {
				f.FixedVersion = ""
			}
			f.CVSS = bestCVSS(v.CVSS)
			res.Findings = append(res.Findings, f)
		}
	}
	return res, nil
}

func bestCVSS(m map[string]struct {
	V3Score  float64 `json:"V3Score"`
	V40Score float64 `json:"V40Score"`
	V2Score  float64 `json:"V2Score"`
}) float64 {
	// Prefer NVD, then GHSA, then any vendor.
	for _, src := range []string{"nvd", "ghsa"} {
		if c, ok := m[src]; ok {
			if c.V40Score > 0 {
				return c.V40Score
			}
			if c.V3Score > 0 {
				return c.V3Score
			}
		}
	}
	best := 0.0
	for _, c := range m {
		best = max(best, c.V40Score, c.V3Score)
	}
	return best
}

// ScanSecrets reads the image from the daemon looking for secrets baked into layers.
func (r *Runner) ScanSecrets(ctx context.Context, imageID string, offline bool) ([]*store.Finding, error) {
	var out bytes.Buffer
	if err := r.run(ctx, offline, &out, r.TrivyBin, "image", "--quiet", "--cache-backend", "memory", "--image-src", "docker", "--format", "json",
		"--scanners", "secret", "--skip-db-update", imageID); err != nil {
		return nil, err
	}
	var rep trivyReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		return nil, err
	}
	var fs []*store.Finding
	for _, rr := range rep.Results {
		for _, s := range rr.Secrets {
			fs = append(fs, &store.Finding{
				Kind:     "secret",
				VulnID:   "SECRET-" + s.RuleID,
				PkgName:  rr.Target,
				PkgPath:  fmt.Sprintf("%s:%d", rr.Target, s.StartLine),
				PkgType:  "secret",
				Severity: normSeverity(s.Severity),
				Title:    s.Title + " (" + s.Category + ")",
				Layer:    s.Layer.DiffID,
				Engines:  "trivy",
			})
		}
	}
	return fs, nil
}

// ---------- Grype ----------

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string   `json:"id"`
			DataSource  string   `json:"dataSource"`
			Severity    string   `json:"severity"`
			URLs        []string `json:"urls"`
			Description string   `json:"description"`
			CVSS        []struct {
				Version string `json:"version"`
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
			Fix struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID          string `json:"id"`
			DataSource  string `json:"dataSource"`
			Description string `json:"description"`
			CVSS        []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path    string `json:"path"`
				LayerID string `json:"layerID"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

func (r *Runner) MatchGrype(ctx context.Context, sbomGz string, offline bool) (*MatchResult, error) {
	path, cleanup, err := readSBOMTo(sbomGz)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var out bytes.Buffer
	if err := r.run(ctx, offline, &out, r.GrypeBin, "sbom:"+path, "-o", "json", "-q"); err != nil {
		return nil, err
	}
	return parseGrype(out.Bytes())
}

func parseGrype(b []byte) (*MatchResult, error) {
	var rep grypeReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}
	res := &MatchResult{}
	for _, m := range rep.Matches {
		v := m.Vulnerability
		id, aliases, desc := v.ID, []string{}, v.Description
		cvss := 0.0
		for _, c := range v.CVSS {
			cvss = max(cvss, c.Metrics.BaseScore)
		}
		// Grype reports GHSA ids for language packages; promote the CVE so
		// results line up with Trivy and with EPSS/KEV.
		for _, rv := range m.RelatedVulnerabilities {
			if strings.HasPrefix(rv.ID, "CVE-") && !strings.HasPrefix(id, "CVE-") {
				aliases = append(aliases, id)
				id = rv.ID
			} else if rv.ID != id {
				aliases = append(aliases, rv.ID)
			}
			if desc == "" {
				desc = rv.Description
			}
			for _, c := range rv.CVSS {
				cvss = max(cvss, c.Metrics.BaseScore)
			}
		}
		fixed := ""
		if v.Fix.State == "fixed" {
			fixed = strings.Join(v.Fix.Versions, ", ")
		}
		f := &store.Finding{
			Kind:         "vuln",
			VulnID:       id,
			Aliases:      strings.Join(dedupe(aliases), ","),
			PkgName:      m.Artifact.Name,
			PkgVersion:   m.Artifact.Version,
			PkgType:      m.Artifact.Type,
			PURL:         m.Artifact.PURL,
			FixedVersion: fixed,
			Severity:     normSeverity(v.Severity),
			CVSS:         cvss,
			Description:  truncate(desc, 1500),
			Title:        firstSentence(desc),
			Engines:      "grype",
		}
		if len(v.URLs) > 0 {
			f.URL = v.URLs[0]
		}
		if v.DataSource != "" && f.URL == "" {
			f.URL = v.DataSource
		}
		for _, l := range m.Artifact.Locations {
			if l.LayerID != "" {
				f.Layer = l.LayerID
				break
			}
		}
		res.Findings = append(res.Findings, f)
	}
	return res, nil
}

// ---------- merge ----------

// Merge combines per-engine findings. A finding is the same if the vuln id
// (or one of its aliases) and the package name+version match. Merged
// findings remember which engines saw them, so the UI can show agreement.
func Merge(sets ...[]*store.Finding) []*store.Finding {
	byKey := map[string]*store.Finding{}
	order := []string{}
	aliasIdx := map[string]string{} // alias|pkg|ver -> key
	for _, set := range sets {
		for _, f := range set {
			k := f.VulnID + "|" + f.PkgName + "|" + f.PkgVersion
			if _, ok := byKey[k]; !ok {
				for _, a := range strings.Split(f.Aliases, ",") {
					if a == "" {
						continue
					}
					if ek, ok := aliasIdx[a+"|"+f.PkgName+"|"+f.PkgVersion]; ok {
						k = ek
						break
					}
				}
			}
			cur, ok := byKey[k]
			if !ok {
				cp := *f
				byKey[k] = &cp
				order = append(order, k)
				aliasIdx[f.VulnID+"|"+f.PkgName+"|"+f.PkgVersion] = k
				for _, a := range strings.Split(f.Aliases, ",") {
					if a != "" {
						aliasIdx[a+"|"+f.PkgName+"|"+f.PkgVersion] = k
					}
				}
				continue
			}
			if !strings.Contains(cur.Engines, f.Engines) {
				cur.Engines += "," + f.Engines
			}
			if sevRank(f.Severity) > sevRank(cur.Severity) {
				cur.Severity = f.Severity
			}
			cur.CVSS = max(cur.CVSS, f.CVSS)
			if cur.FixedVersion == "" {
				cur.FixedVersion = f.FixedVersion
			}
			if cur.Title == "" {
				cur.Title = f.Title
			}
			if cur.Description == "" {
				cur.Description = f.Description
			}
			if cur.Layer == "" {
				cur.Layer = f.Layer
			}
			if cur.PkgPath == "" {
				cur.PkgPath = f.PkgPath
			}
			if f.Aliases != "" {
				cur.Aliases = strings.Join(dedupe(append(strings.Split(cur.Aliases, ","), strings.Split(f.Aliases, ",")...)), ",")
			}
		}
	}
	out := make([]*store.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

// FillLayers attributes findings to layers using the SBOM when the engine did not.
func FillLayers(fs []*store.Finding, info *SBOMInfo) {
	if info == nil {
		return
	}
	for _, f := range fs {
		if f.Layer != "" {
			continue
		}
		if l, ok := info.LayerOf[purlKey(f.PURL)]; ok && f.PURL != "" {
			f.Layer = l
		} else if l, ok := info.LayerOf[f.PkgName+"@"+f.PkgVersion]; ok {
			f.Layer = l
		}
	}
}

// ---------- helpers ----------

func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW", "NEGLIGIBLE":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

func SevRank(s string) int { return sevRank(s) }

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8Start(cut[len(cut)-1]) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

func utf8Start(b byte) bool { return b < 0x80 || b >= 0xC0 }

func cleanTitle(t string) string {
	if t == "Title Not Available" {
		return ""
	}
	return truncate(t, 200)
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 && i < 200 {
		return s[:i]
	}
	return truncate(s, 160)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
