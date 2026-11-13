// Package sqlimpl implements contracts.Store on a SQL database, SQLite in
// practice, reached through gas/database, with its schema applied by
// gas/migrate. Each operation runs in one transaction.
package sqlimpl

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/ids"
)

// Settings configures where the store keeps its data: Path is the SQLite
// database file, created with its directory when it does not exist.
type Settings struct {
	Path string `validate:"required"`
}

// Service stores the functions, the mappings and the invocation history in
// the database db provides.
type Service struct {
	db         gas.DatabaseProvider
	migrations gas.MigrationManager
}

var (
	_ contracts.Store = (*Service)(nil)
	_ gas.Service     = (*Service)(nil)
)

// NewService returns a Service over db, its schema registered with
// migrations.
func NewService(db gas.DatabaseProvider, migrations gas.MigrationManager) *Service {
	return &Service{db: db, migrations: migrations}
}

// Name identifies the service to gas.
func (s *Service) Name() string {
	return "tule/services/functions/sql"
}

// Init registers the schema migrations, which gas applies once every service
// is initialized.
func (s *Service) Init(context.Context) error {
	s.migrations.RegisterSlice(s, migrations)
	return nil
}

// Close releases nothing; the database belongs to the database service.
func (s *Service) Close(context.Context) error {
	return nil
}

// migrations is the store's schema, applied by gas/migrate in version order.
//
// A function's and a mapping's record is JSON text: it is only ever read
// and written whole, and the columns beside it are what listings filter and
// order on. Times are Unix milliseconds. An invocation's payload and result
// are blobs, read only when one invocation is read back whole.
var migrations = []gas.Migration{
	{
		Version:     "0001",
		Description: "create the functions schema",
		Up: `
CREATE TABLE settings (
	name  TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE functions (
	seq    INTEGER PRIMARY KEY AUTOINCREMENT,
	name   TEXT NOT NULL UNIQUE,
	record TEXT NOT NULL
);

CREATE TABLE mappings (
	seq              INTEGER PRIMARY KEY AUTOINCREMENT,
	uuid             TEXT NOT NULL UNIQUE,
	function_name    TEXT NOT NULL,
	event_source_arn TEXT NOT NULL,
	record           TEXT NOT NULL
);
CREATE INDEX mappings_function ON mappings (function_name);
CREATE INDEX mappings_source ON mappings (event_source_arn);

CREATE TABLE invocations (
	seq           INTEGER PRIMARY KEY AUTOINCREMENT,
	request_id    TEXT NOT NULL UNIQUE,
	function_name TEXT NOT NULL,
	started_at    INTEGER NOT NULL,
	source        TEXT NOT NULL,
	status        TEXT NOT NULL,
	duration      REAL NOT NULL,
	attempts      INTEGER NOT NULL,
	error_type    TEXT NOT NULL,
	error_message TEXT NOT NULL,
	payload       BLOB NOT NULL,
	result        BLOB NOT NULL,
	log           TEXT NOT NULL,
	size          INTEGER NOT NULL
);
CREATE INDEX invocations_function ON invocations (function_name, seq);
CREATE INDEX invocations_started_at ON invocations (started_at);
`,
		Down: `
DROP TABLE invocations;
DROP TABLE mappings;
DROP TABLE functions;
DROP TABLE settings;
`,
	},
}

// inTx runs fn in one transaction, which commits only when fn returns nil.
func (s *Service) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if err := s.db.WithTx(ctx, nil, fn); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

// InstanceID returns the store's ID, making it on first use.
func (s *Service) InstanceID(ctx context.Context) (string, error) {
	var id string
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT value FROM settings WHERE name = 'instance'`).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("query: %w", err)
		}
		id = ids.Hex(8)
		_, err = exec(ctx, tx, `INSERT INTO settings (name, value) VALUES ('instance', ?)`, id)
		return err
	})
	return id, err
}

func stamp(t time.Time) int64 {
	return t.UnixMilli()
}

func unstamp(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

func exec(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return res, nil
}

// affected returns how many rows res changed.
func affected(res sql.Result) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// scanner is a row to scan: an *sql.Rows positioned on a row, or an
// *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

// queryAll runs query in tx and scans every row with scan.
func queryAll[T any](
	ctx context.Context,
	tx *sql.Tx,
	scan func(scanner) (T, error),
	query string,
	args ...any,
) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	// Every error of the iteration is reported by rows.Err below; Close
	// after a full iteration has nothing left to report.
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, sErr := scan(rows)
		if sErr != nil {
			return nil, fmt.Errorf("scan: %w", sErr)
		}
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	return string(b), nil
}

func fromJSON(s string, dst any) error {
	if err := json.Unmarshal([]byte(s), dst); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// A page token names the listing it belongs to and the seq of the last item
// it returned, encoded to keep it opaque to clients. A token is only
// accepted back by the listing that issued it.
const tokenSeparator = "\x00"

// The listings a token can belong to.
const (
	listFunctions   = "functions"
	listMappings    = "mappings"
	listInvocations = "invocations"
)

func encodeToken(list string, seq int64) string {
	raw := list + tokenSeparator + strconv.FormatInt(seq, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeToken returns the seq a listing resumes after, or 0 for an empty
// token.
func decodeToken(token, list string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, contracts.ErrInvalidToken
	}
	name, cursor, ok := strings.Cut(string(raw), tokenSeparator)
	if !ok || name != list {
		return 0, contracts.ErrInvalidToken
	}
	seq, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || seq <= 0 {
		return 0, contracts.ErrInvalidToken
	}
	return seq, nil
}

// rowed is one item of a listing with the seq that resumes after it.
type rowed[T any] struct {
	item T
	seq  int64
}

// paginate makes a page of up to size items from rows, which the query
// fetched with one more than size: when that extra row is there, the page has
// a token for the next.
func paginate[T any](rows []rowed[T], size int, list string) *contracts.Page[T] {
	page := &contracts.Page[T]{Items: make([]T, 0, min(len(rows), size))}
	for i, r := range rows {
		if i == size {
			page.NextToken = encodeToken(list, rows[size-1].seq)
			break
		}
		page.Items = append(page.Items, r.item)
	}
	return page
}
