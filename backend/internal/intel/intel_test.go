package intel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

func TestImportFeeds(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	kev := `{"vulnerabilities":[{"cveID":"CVE-2021-44228","vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"},{"cveID":"CVE-2020-1","knownRansomwareCampaignUse":"Unknown"}]}`
	if n, err := ImportKEV(ctx, st, strings.NewReader(kev)); err != nil || n != 2 {
		t.Fatalf("kev: %d %v", n, err)
	}
	epss := "#model_version:v2025.03.14,score_date:2026-10-31T00:00:00+0000\ncve,epss,percentile\nCVE-2021-44228,0.94358,0.99957\nCVE-2020-1,0.00043,0.1\nbroken,line\n"
	if n, err := ImportEPSS(ctx, st, strings.NewReader(epss)); err != nil || n != 2 {
		t.Fatalf("epss: %d %v", n, err)
	}
	in, err := st.LookupIntel(ctx, []string{"CVE-2021-44228", "CVE-2020-1", "CVE-9999-1"})
	if err != nil {
		t.Fatal(err)
	}
	l := in["CVE-2021-44228"]
	if !l.KEV || !l.Ransom || l.EPSS < 0.9 {
		t.Errorf("log4shell intel wrong: %+v", l)
	}
	if in["CVE-2020-1"].Ransom || !in["CVE-2020-1"].KEV {
		t.Errorf("ransomware flag wrong: %+v", in["CVE-2020-1"])
	}
	if _, ok := in["CVE-9999-1"]; ok {
		t.Errorf("unknown CVE should be absent")
	}
	// An empty feed must not wipe existing data.
	if _, err := ImportEPSS(ctx, st, strings.NewReader("cve,epss,percentile\n")); err == nil {
		t.Errorf("empty EPSS feed should error")
	}
	if _, e := st.IntelCounts(ctx); e != 2 {
		t.Errorf("EPSS data was wiped by an empty feed: %d rows", e)
	}
}
