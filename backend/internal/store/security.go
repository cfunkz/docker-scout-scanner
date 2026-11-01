package store

import (
	"context"
	"database/sql"
	"errors"
)

// ---------- two-factor (TOTP) ----------

type TOTP struct {
	UserID   int64
	Secret   string
	Enabled  bool
	LastStep int64
	Recovery []string // sha256 hex of unused recovery codes
}

func (s *Store) GetTOTP(ctx context.Context, userID int64) (*TOTP, error) {
	var t TOTP
	var en int
	var rec string
	err := s.DB.QueryRowContext(ctx, `SELECT user_id,secret,enabled,last_step,recovery FROM totp WHERE user_id=?`, userID).
		Scan(&t.UserID, &t.Secret, &en, &t.LastStep, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	t.Enabled = en == 1
	t.Recovery = fromJSON[[]string](rec)
	return &t, err
}

// SetPendingTOTP stores a new, not yet confirmed secret (replacing any pending one).
func (s *Store) SetPendingTOTP(ctx context.Context, userID int64, secret string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO totp(user_id,secret,enabled,created_at) VALUES(?,?,0,?)
ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, enabled=0, last_step=0, recovery='[]', created_at=excluded.created_at`, userID, secret, Now())
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, recoveryHashes []string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE totp SET enabled=1, last_step=?, recovery=? WHERE user_id=?`, step, toJSON(recoveryHashes), userID)
	return err
}

// UseTOTPStep records an accepted code. It fails if the step was already used.
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) bool {
	res, err := s.DB.ExecContext(ctx, `UPDATE totp SET last_step=? WHERE user_id=? AND last_step<?`, step, userID, step)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// UseRecoveryCode removes one recovery code hash; false if it wasn't there.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, hash string) bool {
	t, err := s.GetTOTP(ctx, userID)
	if err != nil || t == nil {
		return false
	}
	keep := make([]string, 0, len(t.Recovery))
	found := false
	for _, h := range t.Recovery {
		if h == hash && !found {
			found = true
			continue
		}
		keep = append(keep, h)
	}
	if !found {
		return false
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE totp SET recovery=? WHERE user_id=?`, toJSON(keep), userID)
	return err == nil
}

func (s *Store) DeleteTOTP(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM totp WHERE user_id=?`, userID)
	return err
}

// TOTPEnabled returns the ids of users with two-factor turned on.
func (s *Store) TOTPEnabled(ctx context.Context) map[int64]bool {
	out := map[int64]bool{}
	rows, err := s.DB.QueryContext(ctx, `SELECT user_id FROM totp WHERE enabled=1`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// ---------- API tokens ----------

type APIToken struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	TokenHash string `json:"-"`
	Prefix    string `json:"prefix"`
	Scope     string `json:"scope"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	LastUsed  int64  `json:"last_used"`
	LastIP    string `json:"last_ip"`
}

const tokenCols = `t.id,t.user_id,u.username,t.name,t.token_hash,t.prefix,t.scope,t.created_at,t.expires_at,t.last_used,t.last_ip`

func scanToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.UserID, &t.Username, &t.Name, &t.TokenHash, &t.Prefix, &t.Scope, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed, &t.LastIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &t, err
}

func (s *Store) CreateAPIToken(ctx context.Context, t *APIToken) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO api_tokens(user_id,name,token_hash,prefix,scope,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		t.UserID, t.Name, t.TokenHash, t.Prefix, t.Scope, Now(), t.ExpiresAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) APITokenByHash(ctx context.Context, hash string) (*APIToken, error) {
	return scanToken(s.DB.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`, hash))
}

// APITokens lists tokens; userID 0 lists everyone's.
func (s *Store) APITokens(ctx context.Context, userID int64) ([]*APIToken, error) {
	q := `SELECT ` + tokenCols + ` FROM api_tokens t JOIN users u ON u.id=t.user_id`
	args := []any{}
	if userID != 0 {
		q += ` WHERE t.user_id=?`
		args = append(args, userID)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY t.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TouchAPIToken(ctx context.Context, id int64, ip string) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE api_tokens SET last_used=?, last_ip=? WHERE id=?`, Now(), ip, id)
}

// DeleteAPIToken removes a token; userID 0 allows deleting anyone's (admin).
func (s *Store) DeleteAPIToken(ctx context.Context, id, userID int64) (bool, error) {
	q, args := `DELETE FROM api_tokens WHERE id=?`, []any{id}
	if userID != 0 {
		q += ` AND user_id=?`
		args = append(args, userID)
	}
	res, err := s.DB.ExecContext(ctx, q, args...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
