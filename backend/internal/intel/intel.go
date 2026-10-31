// Package intel downloads threat-intelligence feeds that turn a long CVE list
// into a short to-do list: CISA's Known Exploited Vulnerabilities catalog and
// FIRST's EPSS exploit-probability scores.
package intel

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
)

var client = &http.Client{Timeout: 3 * time.Minute}

func fetch(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "docker-scout-scanner")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

func UpdateKEV(ctx context.Context, st *store.Store, url string) (int, error) {
	resp, err := fetch(ctx, url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return ImportKEV(ctx, st, io.LimitReader(resp.Body, 64<<20))
}

func ImportKEV(ctx context.Context, st *store.Store, r io.Reader) (int, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return 0, fmt.Errorf("parse KEV: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return 0, fmt.Errorf("KEV feed is empty")
	}
	entries := make([]store.KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		entries = append(entries, store.KEVEntry{
			CVE: v.CveID, Name: v.VulnerabilityName, DateAdded: v.DateAdded, DueDate: v.DueDate,
			Ransomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		})
	}
	return len(entries), st.ReplaceKEV(ctx, entries)
}

func UpdateEPSS(ctx context.Context, st *store.Store, url string) (int, error) {
	resp, err := fetch(ctx, url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var r io.Reader = io.LimitReader(resp.Body, 256<<20)
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		r = gz
	}
	return ImportEPSS(ctx, st, r)
}

// ImportEPSS parses the FIRST CSV ("#model..." comment, header "cve,epss,percentile").
func ImportEPSS(ctx context.Context, st *store.Store, r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n, err := st.ReplaceEPSS(ctx, func() (store.EPSSEntry, bool, error) {
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "CVE-") {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 3 {
				continue
			}
			score, err1 := strconv.ParseFloat(parts[1], 64)
			pct, err2 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
			if err1 != nil || err2 != nil {
				continue
			}
			return store.EPSSEntry{CVE: parts[0], Score: score, Pct: pct}, true, nil
		}
		return store.EPSSEntry{}, false, sc.Err()
	})
	if err == nil && n == 0 {
		return 0, fmt.Errorf("EPSS feed is empty")
	}
	return n, err
}
