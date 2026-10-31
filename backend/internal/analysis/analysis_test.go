package analysis

import (
	"testing"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/docker"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.10", "1.2.9", 1},
		{"1.2.5-r4", "1.2.5-r3", 1},
		{"1.0", "1.0.0", -1},
		{"v2.0.0", "2.0.0", 0},
		{"1:2.0", "1.9", 1},
		{"3.0.8", "3.1.2", -1},
		{"1.2.3", "1.2.3a", -1},
	}
	for _, c := range cases {
		if got := sign(CompareVersions(c.a, c.b)); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}

func TestPickFixedPrefersSameMajor(t *testing.T) {
	if got := pickFixed("3.1.2, 2.17.1", "2.14.0"); got != "2.17.1" {
		t.Errorf("got %q", got)
	}
	if got := pickFixed("1.2.1-r0", "1.2.0-r1"); got != "1.2.1-r0" {
		t.Errorf("got %q", got)
	}
}

func TestFixPlanGroupsAndRanks(t *testing.T) {
	fs := []*store.Finding{
		{Kind: "vuln", VulnID: "A", PkgName: "curl", PkgVersion: "8.0", FixedVersion: "8.1", Severity: "HIGH", Risk: 40, Layer: "L1"},
		{Kind: "vuln", VulnID: "B", PkgName: "curl", PkgVersion: "8.0", FixedVersion: "8.3", Severity: "CRITICAL", Risk: 50, Layer: "L1"},
		{Kind: "vuln", VulnID: "C", PkgName: "zlib", PkgVersion: "1.0", FixedVersion: "1.1", Severity: "LOW", Risk: 10, KEV: true, Layer: "L0"},
		{Kind: "vuln", VulnID: "D", PkgName: "zlib", PkgVersion: "1.0", Severity: "LOW", Risk: 5, Layer: "L0"},
		{Kind: "vuln", VulnID: "E", PkgName: "x", PkgVersion: "1", FixedVersion: "2", Severity: "HIGH", IgnoredBy: 3},
	}
	im := &store.Image{Layers: []store.Layer{{DiffID: "L0"}, {DiffID: "L1"}}}
	p := BuildFixPlan(fs, im)
	if len(p.Steps) != 2 || p.Unfixable != 1 || p.FixableTotal != 3 {
		t.Fatalf("unexpected plan %+v", p)
	}
	if p.Steps[0].Pkg != "zlib" { // KEV first
		t.Errorf("KEV upgrade should rank first, got %s", p.Steps[0].Pkg)
	}
	if p.Steps[1].Target != "8.3" || p.Steps[1].Fixes != 2 {
		t.Errorf("curl should target 8.3 fixing 2: %+v", p.Steps[1])
	}
	if p.Steps[0].Remaining != 1 {
		t.Errorf("zlib has one unfixed finding left")
	}
	if p.BaseImage == nil || p.BaseImage.Findings != 2 || p.BaseImage.Share != 50 {
		t.Errorf("base hint wrong: %+v", p.BaseImage)
	}
}

func TestGlobImage(t *testing.T) {
	for _, c := range []struct {
		p, n string
		ok   bool
	}{
		{"nginx", "nginx:1.27", true},
		{"nginx", "docker.io/library/nginx:latest", true},
		{"nginx:*", "nginx:alpine", true},
		{"ghcr.io/me/*", "ghcr.io/me/app:1", true},
		{"nginx", "nginx-proxy:1", false},
		{"redis:7", "redis:6", false},
	} {
		if got := GlobImage(c.p, c.n); got != c.ok {
			t.Errorf("GlobImage(%q,%q)=%v", c.p, c.n, got)
		}
	}
}

func TestMatchIgnore(t *testing.T) {
	rules := []*store.IgnoreRule{
		{ID: 1, VulnID: "CVE-1", Pkg: "*", Image: "*", ExpiresAt: 100}, // expired
		{ID: 2, VulnID: "CVE-1", Pkg: "open*", Image: "myapp"},         // scoped
		{ID: 3, VulnID: "*", Pkg: "kernel-headers", Image: "*"},        // package-wide
	}
	f := &store.Finding{VulnID: "CVE-1", PkgName: "openssl"}
	if got := MatchIgnore(rules, f, []string{"myapp:2"}, 200); got != 2 {
		t.Errorf("want rule 2, got %d", got)
	}
	if got := MatchIgnore(rules, f, []string{"other:1"}, 200); got != 0 {
		t.Errorf("rule should not apply to other image, got %d", got)
	}
	if got := MatchIgnore(rules, &store.Finding{VulnID: "CVE-9", PkgName: "kernel-headers"}, nil, 200); got != 3 {
		t.Errorf("want rule 3, got %d", got)
	}
	if got := MatchIgnore(rules, &store.Finding{VulnID: "GHSA-1", Aliases: "CVE-1", PkgName: "openssl"}, []string{"myapp:1"}, 200); got != 2 {
		t.Errorf("alias should match, got %d", got)
	}
}

func TestRiskOrdering(t *testing.T) {
	kev := Risk(&store.Finding{Kind: "vuln", Severity: "HIGH", CVSS: 7.5, KEV: true, EPSS: 0.9, FixedVersion: "1"}, true)
	crit := Risk(&store.Finding{Kind: "vuln", Severity: "CRITICAL", CVSS: 9.8, EPSS: 0.0004}, false)
	low := Risk(&store.Finding{Kind: "vuln", Severity: "LOW"}, false)
	if !(kev > crit && crit > low) {
		t.Errorf("expected exploited HIGH > unexploited CRITICAL > LOW, got %v %v %v", kev, crit, low)
	}
	if kev > 100 {
		t.Errorf("risk must be capped at 100")
	}
}

func TestDiff(t *testing.T) {
	prev := []*store.Finding{{VulnID: "A", PkgName: "p"}, {VulnID: "B", PkgName: "p"}}
	cur := []*store.Finding{{VulnID: "B", PkgName: "p"}, {VulnID: "C", PkgName: "p"}}
	d := DiffFindings(prev, cur)
	if len(d.New) != 1 || d.New[0].VulnID != "C" || len(d.Resolved) != 1 || d.Resolved[0].VulnID != "A" {
		t.Errorf("bad diff %+v", d)
	}
}

func TestMapLayers(t *testing.T) {
	// Newest first, like the Docker API.
	hist := []docker.HistoryItem{
		{CreatedBy: "CMD [\"nginx\"]", Size: 0},
		{CreatedBy: "RUN /bin/sh -c apk add curl # buildkit", Size: 100},
		{CreatedBy: "WORKDIR /app", Size: 0},
		{CreatedBy: "ENV A=b", Size: 0},
		{CreatedBy: "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]", Size: 0},
		{CreatedBy: "/bin/sh -c #(nop) ADD file:abc in / ", Size: 8000},
	}
	ls := MapLayers([]string{"d0", "d1", "d2"}, hist)
	if ls[0].CreatedBy != "ADD file:abc in /" || ls[1].CreatedBy != "WORKDIR /app" || ls[2].CreatedBy != "RUN apk add curl" {
		t.Errorf("bad mapping: %+v", ls)
	}
	// Mismatch: no attribution rather than a wrong one.
	ls = MapLayers([]string{"d0"}, hist)
	if ls[0].CreatedBy != "" {
		t.Errorf("should not guess when counts differ: %+v", ls)
	}
}
