package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

type ScanSummary struct {
	ID            int64   `json:"id"`
	ImageID       string  `json:"image_id"`
	Ref           string  `json:"ref"`
	StartedAt     int64   `json:"started_at"`
	FinishedAt    int64   `json:"finished_at"`
	Status        string  `json:"status"`
	Error         string  `json:"error,omitempty"`
	Engines       string  `json:"engines"`
	Trigger       string  `json:"trigger"`
	DurationMS    int64   `json:"duration_ms"`
	SBOMReused    bool    `json:"sbom_reused"`
	Critical      int     `json:"critical"`
	High          int     `json:"high"`
	Medium        int     `json:"medium"`
	Low           int     `json:"low"`
	Unknown       int     `json:"unknown"`
	Fixable       int     `json:"fixable"`
	KEV           int     `json:"kev"`
	Ignored       int     `json:"ignored"`
	Secrets       int     `json:"secrets"`
	RiskMax       float64 `json:"risk_max"`
	PrevScan      int64   `json:"prev_scan"`
	NewCount      int     `json:"new_count"`
	ResolvedCount int     `json:"resolved_count"`
	Pruned        bool    `json:"pruned"`
}

func (s *ScanSummary) Total() int { return s.Critical + s.High + s.Medium + s.Low + s.Unknown }

type Finding struct {
	ScanID        int64   `json:"-"`
	Kind          string  `json:"kind"`
	VulnID        string  `json:"id"`
	Aliases       string  `json:"aliases,omitempty"`
	PkgName       string  `json:"pkg"`
	PkgVersion    string  `json:"version"`
	PkgType       string  `json:"pkg_type"`
	PURL          string  `json:"purl,omitempty"`
	PkgPath       string  `json:"path,omitempty"`
	FixedVersion  string  `json:"fixed"`
	Severity      string  `json:"severity"`
	CVSS          float64 `json:"cvss"`
	EPSS          float64 `json:"epss"`
	EPSSPct       float64 `json:"epss_pct"`
	KEV           bool    `json:"kev"`
	KEVRansomware bool    `json:"kev_ransomware"`
	Title         string  `json:"title"`
	Description   string  `json:"description,omitempty"`
	URL           string  `json:"url"`
	Published     string  `json:"published,omitempty"`
	Layer         string  `json:"layer,omitempty"`
	Engines       string  `json:"engines"`
	Risk          float64 `json:"risk"`
	IgnoredBy     int64   `json:"ignored_by,omitempty"`
}

// Key identifies a finding across scans, for diffing.
func (f *Finding) Key() string { return f.VulnID + "|" + f.PkgName + "|" + f.PkgPath }

const scanCols = `id,image_id,ref,started_at,finished_at,status,error,engines,trigger,duration_ms,sbom_reused,critical,high,medium,low,unknown,fixable,kev,ignored,secrets,risk_max,prev_scan,new_count,resolved_count,pruned`

func scanScan(row interface{ Scan(...any) error }) (*ScanSummary, error) {
	var sc ScanSummary
	var reused, pruned int
	err := row.Scan(&sc.ID, &sc.ImageID, &sc.Ref, &sc.StartedAt, &sc.FinishedAt, &sc.Status, &sc.Error, &sc.Engines, &sc.Trigger,
		&sc.DurationMS, &reused, &sc.Critical, &sc.High, &sc.Medium, &sc.Low, &sc.Unknown, &sc.Fixable, &sc.KEV, &sc.Ignored,
		&sc.Secrets, &sc.RiskMax, &sc.PrevScan, &sc.NewCount, &sc.ResolvedCount, &pruned)
	sc.SBOMReused, sc.Pruned = reused == 1, pruned == 1
	return &sc, err
}

func (s *Store) GetScan(ctx context.Context, id int64) (*ScanSummary, error) {
	sc, err := scanScan(s.DB.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sc, err
}

func (s *Store) GetScans(ctx context.Context, ids []int64) (map[int64]*ScanSummary, error) {
	out := map[int64]*ScanSummary{}
	for len(ids) > 0 {
		n := min(len(ids), 500)
		chunk := ids[:n]
		ids = ids[n:]
		args := make([]any, len(chunk))
		for i, v := range chunk {
			args[i] = v
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT `+scanCols+` FROM scans WHERE id IN (`+placeholders(len(chunk))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			sc, err := scanScan(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out[sc.ID] = sc
		}
		rows.Close()
	}
	return out, nil
}

// ScanHistory returns the scans of an image and of earlier images that carried the same tag.
func (s *Store) ScanHistory(ctx context.Context, imageID, ref string, limit int) ([]*ScanSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+scanCols+` FROM scans WHERE (image_id=? OR (ref!='' AND ref=?)) AND status!='running' ORDER BY id DESC LIMIT ?`, imageID, ref, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ScanSummary{}
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// PreviousScan finds the most recent successful scan of the same image or the same tag.
func (s *Store) PreviousScan(ctx context.Context, imageID, ref string, before int64) (*ScanSummary, error) {
	sc, err := scanScan(s.DB.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans WHERE (image_id=? OR (ref!='' AND ref=?)) AND status='done' AND pruned=0 AND id<? ORDER BY id DESC LIMIT 1`, imageID, ref, before))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sc, err
}

func (s *Store) StartScan(ctx context.Context, imageID, ref, engines, trigger string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO scans(image_id,ref,started_at,status,engines,trigger) VALUES(?,?,?,?,?,?)`,
		imageID, ref, Now(), "running", engines, trigger)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FailScan(ctx context.Context, id int64, msg string, dur time.Duration) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE scans SET status='failed', error=?, finished_at=?, duration_ms=? WHERE id=?`, msg, Now(), dur.Milliseconds(), id)
}

// RecoverRunning marks scans left 'running' by a crash as failed.
func (s *Store) RecoverRunning(ctx context.Context) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE scans SET status='failed', error='interrupted (restart)' WHERE status='running'`)
}

// FinishScan writes all findings and the summary in one transaction and points the image at the new scan.
func (s *Store) FinishScan(ctx context.Context, sc *ScanSummary, findings []*Finding) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(scan_id,kind,vuln_id,aliases,pkg_name,pkg_version,pkg_type,purl,pkg_path,fixed_version,severity,cvss,epss,epss_pct,kev,kev_ransomware,title,description,url,published,layer,engines,risk,ignored_by)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range findings {
		if _, err := stmt.ExecContext(ctx, sc.ID, f.Kind, f.VulnID, f.Aliases, f.PkgName, f.PkgVersion, f.PkgType, f.PURL, f.PkgPath, f.FixedVersion,
			f.Severity, f.CVSS, f.EPSS, f.EPSSPct, b2i(f.KEV), b2i(f.KEVRansomware), f.Title, f.Description, f.URL, f.Published, f.Layer, f.Engines, f.Risk, f.IgnoredBy); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE scans SET status='done', finished_at=?, duration_ms=?, sbom_reused=?, critical=?, high=?, medium=?, low=?, unknown=?, fixable=?, kev=?, ignored=?, secrets=?, risk_max=?, prev_scan=?, new_count=?, resolved_count=? WHERE id=?`,
		Now(), sc.DurationMS, b2i(sc.SBOMReused), sc.Critical, sc.High, sc.Medium, sc.Low, sc.Unknown, sc.Fixable, sc.KEV, sc.Ignored, sc.Secrets, sc.RiskMax, sc.PrevScan, sc.NewCount, sc.ResolvedCount, sc.ID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE images SET latest_scan=? WHERE id=?`, sc.ID, sc.ImageID); err != nil {
		return err
	}
	return tx.Commit()
}

const findingCols = `kind,vuln_id,aliases,pkg_name,pkg_version,pkg_type,purl,pkg_path,fixed_version,severity,cvss,epss,epss_pct,kev,kev_ransomware,title,description,url,published,layer,engines,risk,ignored_by`

func scanFinding(row interface{ Scan(...any) error }) (*Finding, error) {
	var f Finding
	var kev, ransom int
	err := row.Scan(&f.Kind, &f.VulnID, &f.Aliases, &f.PkgName, &f.PkgVersion, &f.PkgType, &f.PURL, &f.PkgPath, &f.FixedVersion, &f.Severity,
		&f.CVSS, &f.EPSS, &f.EPSSPct, &kev, &ransom, &f.Title, &f.Description, &f.URL, &f.Published, &f.Layer, &f.Engines, &f.Risk, &f.IgnoredBy)
	f.KEV, f.KEVRansomware = kev == 1, ransom == 1
	return &f, err
}

func (s *Store) Findings(ctx context.Context, scanID int64) ([]*Finding, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+findingCols+` FROM findings WHERE scan_id=? ORDER BY risk DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// PruneHistory keeps full findings only for the newest `keep` scans of every image; older scans keep their counts.
func (s *Store) PruneHistory(ctx context.Context, keep int) (int64, error) {
	if keep < 1 {
		keep = 1
	}
	res, err := s.DB.ExecContext(ctx, `
WITH ranked AS (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY image_id ORDER BY id DESC) AS rn FROM scans WHERE pruned=0
)
UPDATE scans SET pruned=1 WHERE id IN (SELECT id FROM ranked WHERE rn>?)`, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, err = s.DB.ExecContext(ctx, `DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE pruned=1)`)
	}
	return n, err
}

// ---------- fleet-wide vulnerability view ----------

type FleetVuln struct {
	VulnID   string   `json:"id"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	EPSS     float64  `json:"epss"`
	KEV      bool     `json:"kev"`
	Title    string   `json:"title"`
	Images   int      `json:"images"`
	InUse    int      `json:"in_use"`
	Packages []string `json:"packages"`
	Fixable  bool     `json:"fixable"`
	Risk     float64  `json:"risk"`
}

// FleetVulns aggregates findings of the latest scan of every present image, by vulnerability.
func (s *Store) FleetVulns(ctx context.Context, q string, limit int) ([]*FleetVuln, error) {
	args := []any{}
	where := `f.kind='vuln' AND f.ignored_by=0`
	if q = strings.TrimSpace(q); q != "" {
		where += ` AND (f.vuln_id LIKE ? OR f.pkg_name LIKE ? OR f.title LIKE ? OR f.aliases LIKE ?)`
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, `
SELECT f.vuln_id, MAX(f.severity='CRITICAL')*4+MAX(f.severity='HIGH')*3+MAX(f.severity='MEDIUM')*2+MAX(f.severity='LOW') AS sev,
       MAX(f.cvss), MAX(f.epss), MAX(f.kev), MAX(f.title), COUNT(DISTINCT i.id),
       COUNT(DISTINCT CASE WHEN i.containers!='[]' THEN i.id END),
       GROUP_CONCAT(DISTINCT f.pkg_name), MAX(f.fixed_version!=''), MAX(f.risk)
FROM images i JOIN findings f ON f.scan_id=i.latest_scan
WHERE i.present=1 AND `+where+`
GROUP BY f.vuln_id ORDER BY MAX(f.risk) DESC, COUNT(DISTINCT i.id) DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FleetVuln{}
	for rows.Next() {
		var v FleetVuln
		var sev, kev, fix int
		var pkgs sql.NullString
		if err := rows.Scan(&v.VulnID, &sev, &v.CVSS, &v.EPSS, &kev, &v.Title, &v.Images, &v.InUse, &pkgs, &fix, &v.Risk); err != nil {
			return nil, err
		}
		v.Severity = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[sev]
		v.KEV, v.Fixable = kev == 1, fix == 1
		v.Packages = strings.Split(pkgs.String, ",")
		out = append(out, &v)
	}
	return out, rows.Err()
}

type AffectedImage struct {
	ImageID    string   `json:"image_id"`
	Name       string   `json:"name"`
	InUse      bool     `json:"in_use"`
	Pkg        string   `json:"pkg"`
	Version    string   `json:"version"`
	Fixed      string   `json:"fixed"`
	Layer      string   `json:"layer"`
	Containers []string `json:"containers"`
}

func (s *Store) VulnDetail(ctx context.Context, vulnID string) (*Finding, []*AffectedImage, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT i.id, i.repo_tags, i.containers, f.pkg_name, f.pkg_version, f.fixed_version, f.layer
FROM images i JOIN findings f ON f.scan_id=i.latest_scan
WHERE i.present=1 AND f.vuln_id=? ORDER BY i.repo_tags`, vulnID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := []*AffectedImage{}
	for rows.Next() {
		var a AffectedImage
		var tags, containers string
		if err := rows.Scan(&a.ImageID, &tags, &containers, &a.Pkg, &a.Version, &a.Fixed, &a.Layer); err != nil {
			return nil, nil, err
		}
		im := Image{ID: a.ImageID, RepoTags: fromJSON[[]string](tags)}
		a.Name = im.Name()
		cs := fromJSON[[]ContainerRef](containers)
		for _, c := range cs {
			a.Containers = append(a.Containers, c.Name)
		}
		a.InUse = len(cs) > 0
		out = append(out, &a)
	}
	f, err := scanFinding(s.DB.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE vuln_id=? ORDER BY scan_id DESC LIMIT 1`, vulnID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, out, nil
	}
	return f, out, err
}

// ---------- snapshots / trend ----------

type Snapshot struct {
	Day      string `json:"day"`
	Images   int    `json:"images"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	KEV      int    `json:"kev"`
	Fixable  int    `json:"fixable"`
}

func (s *Store) TakeSnapshot(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO snapshots(day,images,critical,high,medium,low,kev,fixable)
SELECT date('now'), COUNT(*), COALESCE(SUM(s.critical),0), COALESCE(SUM(s.high),0), COALESCE(SUM(s.medium),0), COALESCE(SUM(s.low),0), COALESCE(SUM(s.kev),0), COALESCE(SUM(s.fixable),0)
FROM images i LEFT JOIN scans s ON s.id=i.latest_scan WHERE i.present=1 AND i.excluded=0
ON CONFLICT(day) DO UPDATE SET images=excluded.images, critical=excluded.critical, high=excluded.high, medium=excluded.medium,
  low=excluded.low, kev=excluded.kev, fixable=excluded.fixable`)
	return err
}

func (s *Store) Trend(ctx context.Context, days int) ([]Snapshot, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT day,images,critical,high,medium,low,kev,fixable FROM snapshots WHERE day>=date('now', ?) ORDER BY day`, "-"+strconv.Itoa(days)+" days")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		var sn Snapshot
		if err := rows.Scan(&sn.Day, &sn.Images, &sn.Critical, &sn.High, &sn.Medium, &sn.Low, &sn.KEV, &sn.Fixable); err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}
