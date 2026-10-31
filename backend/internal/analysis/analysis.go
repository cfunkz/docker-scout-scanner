// Package analysis turns raw findings into decisions: risk scores, accepted-
// risk rules, "what changed since last time" diffs, upgrade plans and layer
// attribution.
package analysis

import (
	"math"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/docker"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

// ---------- risk ----------

var sevBase = map[string]float64{"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2.5, "UNKNOWN": 1}

// Risk is a 0-100 priority score. Severity gives the floor; real-world
// exploitation signals (KEV, EPSS) push it up; a missing fix or an unused
// image pulls it down. The formula is documented in the README and in the UI.
func Risk(f *store.Finding, inUse bool) float64 {
	// The severity band comes from the advisory source that knows the package
	// best (distro tracker, GHSA); CVSS only breaks ties inside the band, or
	// stands in when the severity is unknown.
	sev := sevBase[f.Severity]
	if f.Severity == "UNKNOWN" && f.CVSS > 0 {
		sev = f.CVSS
	}
	score := sev * 4 // 4..38
	if f.CVSS > 0 {
		score += math.Min(f.CVSS, 10) * 0.2 // 0..2
	}
	score += math.Sqrt(f.EPSS) * 30 // 0..30, sqrt so 1% EPSS already counts
	if f.KEV {
		score += 20
	}
	if f.FixedVersion != "" {
		score += 5
	}
	if inUse {
		score += 5
	}
	if f.Kind == "secret" {
		score = 70
		if inUse {
			score += 10
		}
	}
	return math.Round(math.Min(score, 100)*10) / 10
}

// ---------- ignore rules ----------

// MatchIgnore returns the first active rule covering the finding.
func MatchIgnore(rules []*store.IgnoreRule, f *store.Finding, imageNames []string, now int64) int64 {
	for _, r := range rules {
		if r.ExpiresAt > 0 && r.ExpiresAt < now {
			continue
		}
		if r.VulnID != "*" && !strings.EqualFold(r.VulnID, f.VulnID) && !containsFold(f.Aliases, r.VulnID) {
			continue
		}
		if r.Pkg != "" && r.Pkg != "*" {
			if ok, _ := path.Match(r.Pkg, f.PkgName); !ok {
				continue
			}
		}
		if r.Image != "" && r.Image != "*" {
			hit := false
			for _, n := range imageNames {
				if GlobImage(r.Image, n) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		return r.ID
	}
	return 0
}

func containsFold(list, id string) bool {
	for _, a := range strings.Split(list, ",") {
		if strings.EqualFold(a, id) {
			return true
		}
	}
	return false
}

// GlobImage matches a pattern against repo:tag. "nginx" matches "nginx:*" and
// docker.io/library/ prefixes are ignored on both sides.
func GlobImage(pattern, name string) bool {
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "docker.io/")
		return strings.TrimPrefix(s, "library/")
	}
	pattern, name = norm(pattern), norm(name)
	if ok, _ := path.Match(pattern, name); ok {
		return true
	}
	if !strings.Contains(pattern, ":") {
		repo := name
		if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
			repo = name[:i]
		}
		ok, _ := path.Match(pattern, repo)
		return ok
	}
	return false
}

// ---------- diff ----------

type Diff struct {
	New      []*store.Finding `json:"new"`
	Resolved []*store.Finding `json:"resolved"`
}

func DiffFindings(prev, cur []*store.Finding) Diff {
	pk := map[string]bool{}
	for _, f := range prev {
		pk[f.Key()] = true
	}
	ck := map[string]bool{}
	d := Diff{New: []*store.Finding{}, Resolved: []*store.Finding{}}
	for _, f := range cur {
		ck[f.Key()] = true
		if !pk[f.Key()] && f.IgnoredBy == 0 {
			d.New = append(d.New, f)
		}
	}
	for _, f := range prev {
		if !ck[f.Key()] && f.IgnoredBy == 0 {
			d.Resolved = append(d.Resolved, f)
		}
	}
	return d
}

// ---------- fix plan ----------

type FixStep struct {
	Pkg       string   `json:"pkg"`
	PkgType   string   `json:"pkg_type"`
	Installed string   `json:"installed"`
	Target    string   `json:"target"`
	Fixes     int      `json:"fixes"`
	Critical  int      `json:"critical"`
	High      int      `json:"high"`
	KEV       int      `json:"kev"`
	RiskSum   float64  `json:"risk_sum"`
	VulnIDs   []string `json:"vuln_ids"`
	Layer     string   `json:"layer"`
	Remaining int      `json:"remaining"` // findings in the same package with no fix yet
}

type FixPlan struct {
	Steps        []*FixStep `json:"steps"`
	Unfixable    int        `json:"unfixable"`
	FixableTotal int        `json:"fixable_total"`
	BaseImage    *BaseHint  `json:"base_image,omitempty"`
}

type BaseHint struct {
	Layer    string `json:"layer"`
	Findings int    `json:"findings"`
	Fixable  int    `json:"fixable"`
	Share    int    `json:"share_pct"`
	EOSL     bool   `json:"eosl"`
	OS       string `json:"os"`
}

// BuildFixPlan groups fixable findings by package and picks the lowest
// version that clears all of them, ranked by how much risk each upgrade removes.
func BuildFixPlan(fs []*store.Finding, im *store.Image) FixPlan {
	type key struct{ name, ver, typ string }
	steps := map[key]*FixStep{}
	plan := FixPlan{Steps: []*FixStep{}}
	unfixedByPkg := map[key]int{}
	for _, f := range fs {
		if f.IgnoredBy != 0 || f.Kind != "vuln" {
			continue
		}
		k := key{f.PkgName, f.PkgVersion, f.PkgType}
		if f.FixedVersion == "" {
			plan.Unfixable++
			unfixedByPkg[k]++
			continue
		}
		plan.FixableTotal++
		st, ok := steps[k]
		if !ok {
			st = &FixStep{Pkg: f.PkgName, PkgType: f.PkgType, Installed: f.PkgVersion, Layer: f.Layer}
			steps[k] = st
		}
		target := pickFixed(f.FixedVersion, f.PkgVersion)
		if st.Target == "" || CompareVersions(target, st.Target) > 0 {
			st.Target = target
		}
		st.Fixes++
		st.RiskSum += f.Risk
		st.VulnIDs = append(st.VulnIDs, f.VulnID)
		switch f.Severity {
		case "CRITICAL":
			st.Critical++
		case "HIGH":
			st.High++
		}
		if f.KEV {
			st.KEV++
		}
	}
	for k, st := range steps {
		st.Remaining = unfixedByPkg[k]
		st.RiskSum = math.Round(st.RiskSum*10) / 10
		plan.Steps = append(plan.Steps, st)
	}
	sort.Slice(plan.Steps, func(i, j int) bool {
		a, b := plan.Steps[i], plan.Steps[j]
		if a.KEV != b.KEV {
			return a.KEV > b.KEV
		}
		if a.RiskSum != b.RiskSum {
			return a.RiskSum > b.RiskSum
		}
		return a.Pkg < b.Pkg
	})

	// If most findings sit in the bottom layer, rebuilding on a fresh base
	// image is a better first move than patching packages one by one.
	if im != nil && len(im.Layers) > 0 {
		base := im.Layers[0].DiffID
		hint := &BaseHint{Layer: base, EOSL: im.EOSL, OS: strings.TrimSpace(im.OSFamily + " " + im.OSName)}
		total := 0
		for _, f := range fs {
			if f.IgnoredBy != 0 || f.Kind != "vuln" {
				continue
			}
			total++
			if f.Layer == base {
				hint.Findings++
				if f.FixedVersion != "" {
					hint.Fixable++
				}
			}
		}
		if total > 0 {
			hint.Share = hint.Findings * 100 / total
		}
		if hint.Findings > 0 || hint.EOSL {
			plan.BaseImage = hint
		}
	}
	return plan
}

// pickFixed chooses, from a list like "1.2.3, 2.0.1", the smallest version
// above the installed one (same major when possible).
func pickFixed(list, installed string) string {
	cands := []string{}
	for _, v := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' }) {
		if v != "" {
			cands = append(cands, v)
		}
	}
	if len(cands) == 0 {
		return list
	}
	sort.Slice(cands, func(i, j int) bool { return CompareVersions(cands[i], cands[j]) < 0 })
	major := leadingNum(installed)
	for _, c := range cands {
		if CompareVersions(c, installed) > 0 && leadingNum(c) == major {
			return c
		}
	}
	for _, c := range cands {
		if CompareVersions(c, installed) > 0 {
			return c
		}
	}
	return cands[len(cands)-1]
}

func leadingNum(v string) string {
	v = strings.TrimPrefix(v, "v")
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	return v[:i]
}

// CompareVersions is a pragmatic ecosystem-agnostic comparison: it splits
// into numeric and non-numeric runs and compares them pairwise. Good enough to
// order "1.2.10" > "1.2.9" and "1.2.5-r4" > "1.2.5-r3"; exact semantics per
// ecosystem stay with the matchers.
func CompareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	if i := strings.Index(a, ":"); i > 0 && isDigits(a[:i]) { // dpkg epoch
		a = a[i+1:]
	}
	if i := strings.Index(b, ":"); i > 0 && isDigits(b[:i]) {
		b = b[i+1:]
	}
	ta, tb := tokenize(a), tokenize(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if i >= len(ta) {
			return -1
		}
		if i >= len(tb) {
			return 1
		}
		x, y := ta[i], tb[i]
		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		case xn:
			return 1
		case yn:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

func tokenize(s string) []string {
	var out []string
	cur := []rune{}
	digit := false
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		if r == '.' || r == '-' || r == '_' || r == '+' || r == '~' {
			flush()
			continue
		}
		d := unicode.IsDigit(r)
		if len(cur) > 0 && d != digit {
			flush()
		}
		digit = d
		cur = append(cur, r)
	}
	flush()
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ---------- layers ----------

var emptyInstr = []string{"ENV ", "LABEL ", "CMD ", "ENTRYPOINT ", "EXPOSE ", "USER ", "ARG ", "STOPSIGNAL ", "HEALTHCHECK ", "SHELL ", "VOLUME ", "ONBUILD ", "MAINTAINER "}

// MapLayers pairs each rootfs diffID with the Dockerfile instruction that
// created it. Docker's history API doesn't flag empty layers, so we use the
// size and the instruction verb to decide which history rows produced a layer.
func MapLayers(diffIDs []string, hist []docker.HistoryItem) []store.Layer {
	layers := make([]store.Layer, len(diffIDs))
	for i, d := range diffIDs {
		layers[i] = store.Layer{Index: i, DiffID: d}
	}
	// history is newest-first
	rows := make([]docker.HistoryItem, 0, len(hist))
	for i := len(hist) - 1; i >= 0; i-- {
		rows = append(rows, hist[i])
	}
	isLayer := func(h docker.HistoryItem) bool {
		if h.Size > 0 {
			return true
		}
		cb := strings.TrimSpace(strings.TrimPrefix(h.CreatedBy, "/bin/sh -c "))
		if strings.Contains(cb, "#(nop)") {
			return false
		}
		for _, p := range emptyInstr {
			if strings.HasPrefix(cb, p) {
				return false
			}
		}
		return true
	}
	picked := []docker.HistoryItem{}
	for _, h := range rows {
		if isLayer(h) {
			picked = append(picked, h)
		}
	}
	if len(picked) != len(diffIDs) {
		// Fall back to size-only selection before giving up.
		picked = picked[:0]
		for _, h := range rows {
			if h.Size > 0 {
				picked = append(picked, h)
			}
		}
	}
	if len(picked) == len(diffIDs) {
		for i := range layers {
			layers[i].CreatedBy = cleanCreatedBy(picked[i].CreatedBy)
			layers[i].Size = picked[i].Size
		}
	}
	return layers
}

func cleanCreatedBy(s string) string {
	s = strings.TrimPrefix(s, "/bin/sh -c ")
	s = strings.TrimPrefix(s, "#(nop) ")
	s = strings.Replace(s, "RUN /bin/sh -c ", "RUN ", 1)
	if !strings.Contains(s, " ") || isLowerWord(s) {
		s = "RUN " + s
	}
	s = strings.TrimSuffix(s, " # buildkit")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// isLowerWord reports whether a classic-builder command lacks an instruction
// verb (e.g. "apt-get install …" rather than "COPY …").
func isLowerWord(s string) bool {
	verb := s
	if i := strings.IndexByte(s, ' '); i > 0 {
		verb = s[:i]
	}
	return strings.ToUpper(verb) != verb
}
