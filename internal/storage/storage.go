package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("threat not found")
var ErrAlreadyExists = errors.New("threat already exists")

// одна запись
type Threat struct {
	MD5         string
	Name        string
	Type        string
	Severity    string
	Description string
	SHA256      *string
	CVE         []string
	VulnStatus  string
	Playbook    []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Storage struct {
	pool *pgxpool.Pool
}

const columns = `md5, name, type, severity, description, sha256, cve, vuln_status, playbook, created_at, updated_at`

func scanResponse(row pgx.Row) (*Threat, error) {
	var t Threat
	err := row.Scan(&t.MD5, &t.Name, &t.Type, &t.Severity, &t.Description, &t.SHA256, &t.CVE, &t.VulnStatus, &t.Playbook, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// создание бд
func New(ctx context.Context, dsn string) (*Storage, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Storage{pool: pool}, nil
}

// получение записи по md5
func (stg *Storage) Get(ctx context.Context, md5 string) (*Threat, error) {
	row := stg.pool.QueryRow(
		ctx,
		`SELECT `+columns+` FROM threats WHERE md5 = $1`,
		md5)

	t, err := scanResponse(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}
	return t, nil
}

func (stg *Storage) Create(ctx context.Context, t Threat) (*Threat, error) {
	if t.CVE == nil {
		t.CVE = []string{}
	}
	if t.Playbook == nil {
		t.Playbook = []string{}
	}

	row := stg.pool.QueryRow(ctx,
		`INSERT INTO threats (md5, name, type, severity, description, sha256, cve, vuln_status, playbook)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING `+columns,
		t.MD5, t.Name, t.Type, t.Severity, t.Description, t.SHA256, t.CVE, t.VulnStatus, t.Playbook)

	new_t, err := scanResponse(row)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return new_t, nil
}

func (stg *Storage) Update(ctx context.Context, t Threat) (*Threat, error) {
	if t.CVE == nil {
		t.CVE = []string{}
	}
	if t.Playbook == nil {
		t.Playbook = []string{}
	}

	row := stg.pool.QueryRow(
		ctx,
		`UPDATE threats
		 SET name = $2, type = $3, severity = $4, description = $5, sha256 = $6,
		     cve = $7, vuln_status = $8, playbook = $9, updated_at = now()
		 WHERE md5 = $1
		 RETURNING `+columns,
		t.MD5, t.Name, t.Type, t.Severity, t.Description, t.SHA256, t.CVE, t.VulnStatus, t.Playbook)

	updated, err := scanResponse(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *Storage) Close() {
	s.pool.Close()
}
