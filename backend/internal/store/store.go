// Package store owns the SQLite database: schema, migrations and queries.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id            TEXT PRIMARY KEY,            -- sha256 image id
  repo_tags     TEXT NOT NULL DEFAULT '[]',  -- JSON array
  repo_digests  TEXT NOT NULL DEFAULT '[]',
  created       INTEGER NOT NULL DEFAULT 0,
  size          INTEGER NOT NULL DEFAULT 0,
  os            TEXT NOT NULL DEFAULT '',
  arch          TEXT NOT NULL DEFAULT '',
  os_family     TEXT NOT NULL DEFAULT '',
  os_name       TEXT NOT NULL DEFAULT '',
  eosl          INTEGER NOT NULL DEFAULT 0,
  layers        TEXT NOT NULL DEFAULT '[]',  -- JSON [{diff_id, created_by, size}]
  sbom_path     TEXT NOT NULL DEFAULT '',
  pkg_count     INTEGER NOT NULL DEFAULT 0,
  present       INTEGER NOT NULL DEFAULT 1,
  containers    TEXT NOT NULL DEFAULT '[]',  -- JSON [{name,state}]
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  latest_scan   INTEGER NOT NULL DEFAULT 0,
  excluded      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  image_id      TEXT NOT NULL,
  ref           TEXT NOT NULL DEFAULT '',     -- repo:tag used to identify the image across rebuilds
  started_at    INTEGER NOT NULL,
  finished_at   INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL,                -- running|done|failed
  error         TEXT NOT NULL DEFAULT '',
  engines       TEXT NOT NULL DEFAULT '',
  trigger       TEXT NOT NULL DEFAULT '',
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  sbom_reused   INTEGER NOT NULL DEFAULT 0,
  critical      INTEGER NOT NULL DEFAULT 0,
  high          INTEGER NOT NULL DEFAULT 0,
  medium        INTEGER NOT NULL DEFAULT 0,
  low           INTEGER NOT NULL DEFAULT 0,
  unknown       INTEGER NOT NULL DEFAULT 0,
  fixable       INTEGER NOT NULL DEFAULT 0,
  kev           INTEGER NOT NULL DEFAULT 0,
  ignored       INTEGER NOT NULL DEFAULT 0,
  secrets       INTEGER NOT NULL DEFAULT 0,
  risk_max      REAL NOT NULL DEFAULT 0,
  prev_scan     INTEGER NOT NULL DEFAULT 0,
  new_count     INTEGER NOT NULL DEFAULT 0,
  resolved_count INTEGER NOT NULL DEFAULT 0,
  pruned        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS scans_image ON scans(image_id, id);
CREATE INDEX IF NOT EXISTS scans_ref ON scans(ref, id);

CREATE TABLE IF NOT EXISTS findings (
  scan_id       INTEGER NOT NULL,
  vuln_id       TEXT NOT NULL,
  aliases       TEXT NOT NULL DEFAULT '',
  pkg_name      TEXT NOT NULL,
  pkg_version   TEXT NOT NULL,
  pkg_type      TEXT NOT NULL DEFAULT '',
  purl          TEXT NOT NULL DEFAULT '',
  pkg_path      TEXT NOT NULL DEFAULT '',
  fixed_version TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL,
  cvss          REAL NOT NULL DEFAULT 0,
  epss          REAL NOT NULL DEFAULT 0,
  epss_pct      REAL NOT NULL DEFAULT 0,
  kev           INTEGER NOT NULL DEFAULT 0,
  kev_ransomware INTEGER NOT NULL DEFAULT 0,
  title         TEXT NOT NULL DEFAULT '',
  description   TEXT NOT NULL DEFAULT '',
  url           TEXT NOT NULL DEFAULT '',
  published     TEXT NOT NULL DEFAULT '',
  layer         TEXT NOT NULL DEFAULT '',
  engines       TEXT NOT NULL DEFAULT '',
  risk          REAL NOT NULL DEFAULT 0,
  ignored_by    INTEGER NOT NULL DEFAULT 0,
  kind          TEXT NOT NULL DEFAULT 'vuln'    -- vuln|secret
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_vuln ON findings(vuln_id);

CREATE TABLE IF NOT EXISTS ignore_rules (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id     TEXT NOT NULL,               -- exact id or '*'
  pkg         TEXT NOT NULL DEFAULT '*',   -- glob
  image       TEXT NOT NULL DEFAULT '*',   -- glob on repo:tag
  status      TEXT NOT NULL DEFAULT 'not_affected', -- OpenVEX status
  justification TEXT NOT NULL DEFAULT '',
  reason      TEXT NOT NULL DEFAULT '',
  expires_at  INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass_hash    TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'viewer',  -- viewer|admin
  must_change  INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  last_login   INTEGER NOT NULL DEFAULT 0,
  failed       INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  scope       TEXT NOT NULL,           -- dashboard|admin
  csrf        TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  ip          TEXT NOT NULL DEFAULT '',
  user_agent  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  actor   TEXT NOT NULL,
  ip      TEXT NOT NULL DEFAULT '',
  action  TEXT NOT NULL,
  detail  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS kev (
  cve        TEXT PRIMARY KEY,
  date_added TEXT NOT NULL DEFAULT '',
  due_date   TEXT NOT NULL DEFAULT '',
  ransomware INTEGER NOT NULL DEFAULT 0,
  name       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS epss (
  cve   TEXT PRIMARY KEY,
  score REAL NOT NULL,
  pct   REAL NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS snapshots (
  day      TEXT PRIMARY KEY,   -- YYYY-MM-DD
  images   INTEGER NOT NULL,
  critical INTEGER NOT NULL,
  high     INTEGER NOT NULL,
  medium   INTEGER NOT NULL,
  low      INTEGER NOT NULL,
  kev      INTEGER NOT NULL,
  fixable  INTEGER NOT NULL
);
`

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{DB: db}, nil
}

func Now() int64 { return time.Now().Unix() }

// ---------- settings ----------

func (s *Store) GetSetting(ctx context.Context, key string) (string, bool) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err != nil {
		return "", false
	}
	return v, true
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---------- audit ----------

func (s *Store) Audit(ctx context.Context, actor, ip, action, detail string) {
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO audit(ts,actor,ip,action,detail) VALUES(?,?,?,?,?)`, Now(), actor, ip, action, detail)
}

type AuditEntry struct {
	ID     int64  `json:"id"`
	TS     int64  `json:"ts"`
	Actor  string `json:"actor"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,ts,actor,ip,action,detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.IP, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- helpers ----------

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON[T any](s string) T {
	var v T
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
