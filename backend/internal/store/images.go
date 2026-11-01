package store

import (
	"context"
	"database/sql"
	"errors"
)

type Layer struct {
	Index     int    `json:"index"`
	DiffID    string `json:"diff_id"`
	CreatedBy string `json:"created_by"`
	Size      int64  `json:"size"`
}

type ContainerRef struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type Image struct {
	ID          string         `json:"id"`
	RepoTags    []string       `json:"repo_tags"`
	RepoDigests []string       `json:"repo_digests"`
	Created     int64          `json:"created"`
	Size        int64          `json:"size"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	OSFamily    string         `json:"os_family"`
	OSName      string         `json:"os_name"`
	EOSL        bool           `json:"eosl"`
	Layers      []Layer        `json:"layers,omitempty"`
	SBOMPath    string         `json:"-"`
	PkgCount    int            `json:"pkg_count"`
	Present     bool           `json:"present"`
	Containers  []ContainerRef `json:"containers"`
	FirstSeen   int64          `json:"first_seen"`
	LastSeen    int64          `json:"last_seen"`
	LatestScan  int64          `json:"latest_scan"`
	Excluded    bool           `json:"excluded"`

	// Joined from latest scan
	Scan *ScanSummary `json:"scan,omitempty"`
}

// Name returns the best human name for an image.
func (i *Image) Name() string {
	if len(i.RepoTags) > 0 {
		return i.RepoTags[0]
	}
	if len(i.RepoDigests) > 0 {
		return i.RepoDigests[0]
	}
	if len(i.ID) > 19 {
		return i.ID[7:19]
	}
	return i.ID
}

const imageCols = `id,repo_tags,repo_digests,created,size,os,arch,os_family,os_name,eosl,layers,sbom_path,pkg_count,present,containers,first_seen,last_seen,latest_scan,excluded`

func scanImage(row interface{ Scan(...any) error }) (*Image, error) {
	var im Image
	var tags, digests, layers, containers string
	var eosl, present, excluded int
	err := row.Scan(&im.ID, &tags, &digests, &im.Created, &im.Size, &im.OS, &im.Arch, &im.OSFamily, &im.OSName, &eosl,
		&layers, &im.SBOMPath, &im.PkgCount, &present, &containers, &im.FirstSeen, &im.LastSeen, &im.LatestScan, &excluded)
	if err != nil {
		return nil, err
	}
	im.RepoTags = fromJSON[[]string](tags)
	im.RepoDigests = fromJSON[[]string](digests)
	im.Layers = fromJSON[[]Layer](layers)
	im.Containers = fromJSON[[]ContainerRef](containers)
	if im.RepoTags == nil {
		im.RepoTags = []string{}
	}
	if im.Containers == nil {
		im.Containers = []ContainerRef{}
	}
	im.EOSL, im.Present, im.Excluded = eosl == 1, present == 1, excluded == 1
	return &im, nil
}

// UpsertSeen records an image observed on the docker host.
func (s *Store) UpsertSeen(ctx context.Context, im *Image) error {
	now := Now()
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO images(id,repo_tags,repo_digests,created,size,os,arch,present,containers,first_seen,last_seen,excluded)
VALUES(?,?,?,?,?,?,?,1,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET repo_tags=excluded.repo_tags, repo_digests=excluded.repo_digests, size=excluded.size,
  present=1, containers=excluded.containers, last_seen=excluded.last_seen, excluded=excluded.excluded,
  os=CASE WHEN excluded.os!='' THEN excluded.os ELSE images.os END,
  arch=CASE WHEN excluded.arch!='' THEN excluded.arch ELSE images.arch END`,
		im.ID, toJSON(im.RepoTags), toJSON(im.RepoDigests), im.Created, im.Size, im.OS, im.Arch,
		toJSON(im.Containers), now, now, b2i(im.Excluded))
	return err
}

// MarkAbsent flags every image not in `present` as gone from the host.
func (s *Store) MarkAbsent(ctx context.Context, present []string) error {
	if len(present) == 0 {
		_, err := s.DB.ExecContext(ctx, `UPDATE images SET present=0, containers='[]'`)
		return err
	}
	args := make([]any, len(present))
	for i, p := range present {
		args[i] = p
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE images SET present=0, containers='[]' WHERE id NOT IN (`+placeholders(len(present))+`)`, args...)
	return err
}

func (s *Store) SetImageSBOM(ctx context.Context, id, path, osFamily, osName string, eosl bool, pkgCount int, layers []Layer) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE images SET sbom_path=?, os_family=?, os_name=?, eosl=?, pkg_count=?, layers=? WHERE id=?`,
		path, osFamily, osName, b2i(eosl), pkgCount, toJSON(layers), id)
	return err
}

func (s *Store) ClearSBOMs(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE images SET sbom_path=''`)
	return err
}

func (s *Store) GetImage(ctx context.Context, id string) (*Image, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT `+imageCols+` FROM images WHERE id=? OR substr(id,8,12)=?`, id, id)
	im, err := scanImage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if im.LatestScan > 0 {
		im.Scan, _ = s.GetScan(ctx, im.LatestScan)
	}
	return im, nil
}

// ListImages returns images (present only unless all=true) joined with their latest scan.
func (s *Store) ListImages(ctx context.Context, all bool) ([]*Image, error) {
	q := `SELECT ` + imageCols + ` FROM images`
	if !all {
		q += ` WHERE present=1`
	}
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Image
	ids := []int64{}
	for rows.Next() {
		im, err := scanImage(rows)
		if err != nil {
			return nil, err
		}
		im.Layers = nil
		out = append(out, im)
		if im.LatestScan > 0 {
			ids = append(ids, im.LatestScan)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	scans, err := s.GetScans(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, im := range out {
		im.Scan = scans[im.LatestScan]
	}
	return out, nil
}

func (s *Store) DeleteAbsentImages(ctx context.Context) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `DELETE FROM findings WHERE scan_id IN (SELECT s.id FROM scans s JOIN images i ON i.id=s.image_id WHERE i.present=0)`)
	_, _ = tx.ExecContext(ctx, `DELETE FROM scans WHERE image_id IN (SELECT id FROM images WHERE present=0)`)
	res, err := tx.ExecContext(ctx, `DELETE FROM images WHERE present=0`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
