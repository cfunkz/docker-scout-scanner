package engine

import (
	"os"
	"testing"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

func TestParseTrivy(t *testing.T) {
	b, err := os.ReadFile("testdata/trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := parseTrivy(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 6 {
		t.Fatalf("want 6 findings, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.VulnID != "CVE-2026-111497" || f.PkgName != "brotli-libs" || f.Severity != "CRITICAL" || f.FixedVersion != "1.2.1-r0" {
		t.Errorf("unexpected first finding %+v", f)
	}
	if f.CVSS == 0 || f.Layer == "" || f.Engines != "trivy" || f.PkgType != "alpine" {
		t.Errorf("missing enrichment from trivy: cvss=%v layer=%q engines=%q type=%q", f.CVSS, f.Layer, f.Engines, f.PkgType)
	}
	if res.OSFamily != "alpine" {
		t.Errorf("os family %q", res.OSFamily)
	}
}

const grypeSample = `{"matches":[
 {"vulnerability":{"id":"GHSA-aaaa-bbbb-cccc","dataSource":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","severity":"High",
   "urls":["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],"description":"Prototype pollution. More text.",
   "cvss":[{"version":"3.1","metrics":{"baseScore":7.5}}],"fix":{"versions":["4.17.21"],"state":"fixed"}},
  "relatedVulnerabilities":[{"id":"CVE-2021-23337","dataSource":"nvd","description":"nvd text","cvss":[{"metrics":{"baseScore":7.2}}]}],
  "artifact":{"name":"lodash","version":"4.17.20","type":"npm","purl":"pkg:npm/lodash@4.17.20","locations":[{"path":"/app/node_modules/lodash/package.json","layerID":"sha256:layer2"}]}},
 {"vulnerability":{"id":"CVE-2026-111497","severity":"Negligible","fix":{"versions":[],"state":"not-fixed"}},
  "artifact":{"name":"brotli-libs","version":"1.2.0-r1","type":"apk","purl":"pkg:apk/alpine/brotli-libs@1.2.0-r1?distro=alpine-3.24.3","locations":[]}}
]}`

func TestParseGrypePromotesCVE(t *testing.T) {
	res, err := parseGrype([]byte(grypeSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.VulnID != "CVE-2021-23337" || f.Aliases != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("GHSA should be promoted to CVE: id=%s aliases=%s", f.VulnID, f.Aliases)
	}
	if f.Severity != "HIGH" || f.CVSS != 7.5 || f.FixedVersion != "4.17.21" || f.Layer != "sha256:layer2" {
		t.Errorf("unexpected %+v", f)
	}
	if res.Findings[1].Severity != "LOW" || res.Findings[1].FixedVersion != "" {
		t.Errorf("negligible should map to LOW with no fix: %+v", res.Findings[1])
	}
}

func TestMergeMarksAgreement(t *testing.T) {
	tr := []*store.Finding{
		{VulnID: "CVE-1", PkgName: "a", PkgVersion: "1", Severity: "MEDIUM", Engines: "trivy", Title: "t"},
		{VulnID: "CVE-2", PkgName: "b", PkgVersion: "1", Severity: "LOW", Engines: "trivy"},
	}
	gr := []*store.Finding{
		{VulnID: "CVE-1", PkgName: "a", PkgVersion: "1", Severity: "HIGH", Engines: "grype", FixedVersion: "2", CVSS: 8},
		{VulnID: "GHSA-x", Aliases: "CVE-2", PkgName: "b", PkgVersion: "1", Severity: "LOW", Engines: "grype"},
		{VulnID: "CVE-3", PkgName: "c", PkgVersion: "1", Severity: "LOW", Engines: "grype"},
	}
	m := Merge(tr, gr)
	if len(m) != 3 {
		t.Fatalf("want 3 merged findings, got %d", len(m))
	}
	if m[0].Engines != "trivy,grype" || m[0].Severity != "HIGH" || m[0].FixedVersion != "2" || m[0].CVSS != 8 || m[0].Title != "t" {
		t.Errorf("merge lost data: %+v", m[0])
	}
	if m[1].Engines != "trivy,grype" {
		t.Errorf("alias match failed: %+v", m[1])
	}
}

func TestFillLayers(t *testing.T) {
	fs := []*store.Finding{{PkgName: "x", PkgVersion: "1", PURL: "pkg:apk/alpine/x@1?distro=alpine-3.20"}}
	FillLayers(fs, &SBOMInfo{LayerOf: map[string]string{"pkg:apk/alpine/x@1": "sha256:l1"}})
	if fs[0].Layer != "sha256:l1" {
		t.Fatalf("layer not filled: %q", fs[0].Layer)
	}
}
