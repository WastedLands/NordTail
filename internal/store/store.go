// Package store persists regions in SQLite. Secret material (the provider
// config, which contains the WireGuard private key) is sealed with the
// master key; the database never holds it in plaintext.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/WastedLands/NordTail/internal/secret"
)

var ErrExists = errors.New("region already exists")
var ErrNotFound = errors.New("region not found")

type Region struct {
	ID        string
	Provider  string
	Config    secret.String // provider config, e.g. wg-quick text
	Port      int           // tailscaled UDP port
	CreatedAt time.Time
}

type Store struct {
	db *sql.DB
	mk *secret.MasterKey
}

func Open(path string, mk *secret.MasterKey) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS regions (
		id         TEXT PRIMARY KEY,
		provider   TEXT NOT NULL,
		config     BLOB NOT NULL,
		port       INTEGER NOT NULL UNIQUE,
		created_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, mk: mk}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func aad(id string) string { return "region:" + id }

// Create inserts a region with the lowest free port in [portMin, portMax].
func (s *Store) Create(ctx context.Context, id, provider string, cfg secret.String, portMin, portMax int) (*Region, error) {
	sealed, err := s.mk.Seal(cfg, aad(id))
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM regions WHERE id = ?`, id).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrExists
	}
	used := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT port FROM regions`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		used[p] = true
	}
	rows.Close()
	port := 0
	for p := portMin; p <= portMax; p++ {
		if !used[p] {
			port = p
			break
		}
	}
	if port == 0 {
		return nil, fmt.Errorf("no free region port in %d-%d", portMin, portMax)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO regions (id, provider, config, port, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, provider, sealed, port, now.Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Region{ID: id, Provider: provider, Config: cfg, Port: port, CreatedAt: now}, nil
}

func (s *Store) List(ctx context.Context) ([]*Region, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, provider, config, port, created_at FROM regions ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Region
	for rows.Next() {
		var r Region
		var sealed []byte
		var created int64
		if err := rows.Scan(&r.ID, &r.Provider, &sealed, &r.Port, &created); err != nil {
			return nil, err
		}
		if r.Config, err = s.mk.Open(sealed, aad(r.ID)); err != nil {
			return nil, fmt.Errorf("region %s: %w", r.ID, err)
		}
		r.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM regions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
