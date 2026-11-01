package store

import (
	"context"
	"database/sql"
	"errors"
)

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	PassHash    string `json:"-"`
	Role        string `json:"role"`
	MustChange  bool   `json:"must_change"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login"`
	Failed      int    `json:"failed"`
	LockedUntil int64  `json:"locked_until"`
}

const userCols = `id,username,pass_hash,role,must_change,created_at,last_login,failed,locked_until`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var mc int
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &mc, &u.CreatedAt, &u.LastLogin, &u.Failed, &u.LockedUntil)
	u.MustChange = mc == 1
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &u, err
}

func (s *Store) UserCount(ctx context.Context) int {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username=?`, name))
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, name, hash, role string, mustChange bool) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users(username,pass_hash,role,must_change,created_at) VALUES(?,?,?,?,?)`, name, hash, role, b2i(mustChange), Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET pass_hash=?, must_change=?, failed=0, locked_until=0 WHERE id=?`, hash, b2i(mustChange), id)
	return err
}

func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id)
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM totp WHERE user_id=?`, id)
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM api_tokens WHERE user_id=?`, id)
	_, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) AdminCount(ctx context.Context) int {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n
}

func (s *Store) LoginFailed(ctx context.Context, id int64, failed int, lockedUntil int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET failed=?, locked_until=? WHERE id=?`, failed, lockedUntil, id)
}

func (s *Store) LoginOK(ctx context.Context, id int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET failed=0, locked_until=0, last_login=? WHERE id=?`, Now(), id)
}

// ---------- sessions ----------

type Session struct {
	TokenHash string `json:"-"`
	ID        string `json:"id"` // short public id (prefix of hash) for revocation
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Scope     string `json:"scope"`
	CSRF      string `json:"-"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	LastSeen  int64  `json:"last_seen"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

func (s *Store) CreateSession(ctx context.Context, se *Session) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,scope,csrf,created_at,expires_at,last_seen,ip,user_agent) VALUES(?,?,?,?,?,?,?,?,?)`,
		se.TokenHash, se.UserID, se.Scope, se.CSRF, se.CreatedAt, se.ExpiresAt, se.LastSeen, se.IP, se.UserAgent)
	return err
}

func (s *Store) GetSession(ctx context.Context, hash string) (*Session, error) {
	var se Session
	err := s.DB.QueryRowContext(ctx, `SELECT s.token_hash,s.user_id,u.username,s.scope,s.csrf,s.created_at,s.expires_at,s.last_seen,s.ip,s.user_agent
FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hash).Scan(&se.TokenHash, &se.UserID, &se.Username, &se.Scope, &se.CSRF, &se.CreatedAt, &se.ExpiresAt, &se.LastSeen, &se.IP, &se.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &se, err
}

func (s *Store) TouchSession(ctx context.Context, hash string, expires int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen=?, expires_at=? WHERE token_hash=?`, Now(), expires, hash)
}

func (s *Store) DeleteSession(ctx context.Context, hash string) {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash)
}

func (s *Store) DeleteSessionByPrefix(ctx context.Context, prefix string) error {
	if len(prefix) < 12 {
		return errors.New("bad session id")
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE substr(token_hash,1,?)=?`, len(prefix), prefix)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND token_hash!=?`, userID, exceptHash)
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<?`, Now())
}

func (s *Store) Sessions(ctx context.Context) ([]*Session, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT s.token_hash,s.user_id,u.username,s.scope,s.created_at,s.expires_at,s.last_seen,s.ip,s.user_agent
FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.expires_at>? ORDER BY s.last_seen DESC`, Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Session{}
	for rows.Next() {
		var se Session
		if err := rows.Scan(&se.TokenHash, &se.UserID, &se.Username, &se.Scope, &se.CreatedAt, &se.ExpiresAt, &se.LastSeen, &se.IP, &se.UserAgent); err != nil {
			return nil, err
		}
		se.ID = se.TokenHash[:16]
		out = append(out, &se)
	}
	return out, rows.Err()
}

// ---------- ignore rules (accepted risk / VEX) ----------

type IgnoreRule struct {
	ID            int64  `json:"id"`
	VulnID        string `json:"vuln_id"`
	Pkg           string `json:"pkg"`
	Image         string `json:"image"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Reason        string `json:"reason"`
	ExpiresAt     int64  `json:"expires_at"`
	CreatedBy     string `json:"created_by"`
	CreatedAt     int64  `json:"created_at"`
}

func (s *Store) IgnoreRules(ctx context.Context) ([]*IgnoreRule, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,vuln_id,pkg,image,status,justification,reason,expires_at,created_by,created_at FROM ignore_rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IgnoreRule{}
	for rows.Next() {
		var r IgnoreRule
		if err := rows.Scan(&r.ID, &r.VulnID, &r.Pkg, &r.Image, &r.Status, &r.Justification, &r.Reason, &r.ExpiresAt, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) AddIgnoreRule(ctx context.Context, r *IgnoreRule) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO ignore_rules(vuln_id,pkg,image,status,justification,reason,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		r.VulnID, r.Pkg, r.Image, r.Status, r.Justification, r.Reason, r.ExpiresAt, r.CreatedBy, Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteIgnoreRule(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM ignore_rules WHERE id=?`, id)
	return err
}

// ---------- KEV / EPSS ----------

type KEVEntry struct {
	CVE        string
	DateAdded  string
	DueDate    string
	Ransomware bool
	Name       string
}

func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO kev(cve,date_added,due_date,ransomware,name) VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.CVE, e.DateAdded, e.DueDate, b2i(e.Ransomware), e.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type EPSSEntry struct {
	CVE   string
	Score float64
	Pct   float64
}

// ReplaceEPSS streams rows from next() into the table inside one transaction.
func (s *Store) ReplaceEPSS(ctx context.Context, next func() (EPSSEntry, bool, error)) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM epss`); err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO epss(cve,score,pct) VALUES(?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	n := 0
	for {
		e, ok, err := next()
		if err != nil {
			return 0, err
		}
		if !ok {
			break
		}
		if _, err := stmt.ExecContext(ctx, e.CVE, e.Score, e.Pct); err != nil {
			return 0, err
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("feed is empty; keeping previous data")
	}
	return n, tx.Commit()
}

type Intel struct {
	EPSS, EPSSPct float64
	KEV, Ransom   bool
}

// LookupIntel returns EPSS/KEV data for a set of CVE ids.
func (s *Store) LookupIntel(ctx context.Context, cves []string) (map[string]Intel, error) {
	out := make(map[string]Intel, len(cves))
	for len(cves) > 0 {
		n := min(len(cves), 500)
		chunk := cves[:n]
		cves = cves[n:]
		args := make([]any, len(chunk))
		for i, c := range chunk {
			args[i] = c
		}
		ph := placeholders(len(chunk))
		rows, err := s.DB.QueryContext(ctx, `SELECT cve,score,pct FROM epss WHERE cve IN (`+ph+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			var in Intel
			if err := rows.Scan(&c, &in.EPSS, &in.EPSSPct); err == nil {
				out[c] = in
			}
		}
		rows.Close()
		rows, err = s.DB.QueryContext(ctx, `SELECT cve,ransomware FROM kev WHERE cve IN (`+ph+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			var r int
			if err := rows.Scan(&c, &r); err == nil {
				in := out[c]
				in.KEV, in.Ransom = true, r == 1
				out[c] = in
			}
		}
		rows.Close()
	}
	return out, nil
}

func (s *Store) IntelCounts(ctx context.Context) (kev, epss int) {
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev`).Scan(&kev)
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM epss`).Scan(&epss)
	return
}
