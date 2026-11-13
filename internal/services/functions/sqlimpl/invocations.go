package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"tule.dev/functions/internal/contracts"
)

// PutInvocation records inv as the newest invocation, replacing an earlier
// record of the same request, and drops the oldest beyond bounds: past
// bounds.Rows, or once the newer ones' payloads, results and logs reach
// bounds.Bytes. The newest is always kept.
func (s *Service) PutInvocation(
	ctx context.Context,
	inv *contracts.Invocation,
	bounds contracts.HistoryBounds,
) error {
	payload, result := truncate(nonNil(inv.Payload)), truncate(nonNil(inv.Result))
	log := string(truncate([]byte(inv.Log)))
	size := len(payload) + len(result) + len(log)
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := exec(ctx, tx, `DELETE FROM invocations WHERE request_id = ?`,
			inv.RequestID); err != nil {
			return err
		}
		if _, err := exec(ctx, tx,
			`INSERT INTO invocations (request_id, function_name, started_at, source, status,
				duration, attempts, error_type, error_message, payload, result, log, size)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			inv.RequestID, inv.Function, stamp(inv.Time), inv.Source, inv.Status,
			inv.Duration, inv.Attempts, inv.ErrorType, inv.ErrorMessage,
			payload, result, log, size); err != nil {
			return err
		}
		if _, err := exec(ctx, tx,
			`DELETE FROM invocations WHERE seq <= (
				SELECT seq FROM invocations ORDER BY seq DESC LIMIT 1 OFFSET ?)`,
			bounds.Rows); err != nil {
			return err
		}
		// The oldest invocation past which the newer ones hold more than
		// bounds.Bytes, the newest excepted, and every older one, go.
		_, err := exec(ctx, tx,
			`DELETE FROM invocations WHERE seq <= (
				SELECT seq FROM (
					SELECT seq, SUM(size) OVER (ORDER BY seq DESC) AS total,
						ROW_NUMBER() OVER (ORDER BY seq DESC) AS n
					FROM invocations)
				WHERE total > ? AND n > 1 ORDER BY seq DESC LIMIT 1)`, bounds.Bytes)
		return err
	})
}

// truncate cuts b to contracts.MaxHistoryField, ending it with
// contracts.TruncatedMarker.
func truncate(b []byte) []byte {
	if len(b) <= contracts.MaxHistoryField {
		return b
	}
	keep := contracts.MaxHistoryField - len(contracts.TruncatedMarker)
	out := make([]byte, 0, contracts.MaxHistoryField)
	return append(append(out, b[:keep]...), contracts.TruncatedMarker...)
}

// nonNil returns b, or an empty slice for nil, which the NOT NULL blob
// columns take.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// summaryColumns are the columns of a listed invocation; detailColumns add
// the payload, the result and the log.
const (
	summaryColumns = `seq, request_id, function_name, started_at, source, status, duration,
		attempts, error_type, error_message`
	detailColumns = summaryColumns + `, payload, result, log`
)

func scanSummary(row scanner) (rowed[contracts.Invocation], error) {
	var (
		r  rowed[contracts.Invocation]
		at int64
	)
	inv := &r.item
	if err := row.Scan(&r.seq, &inv.RequestID, &inv.Function, &at, &inv.Source, &inv.Status,
		&inv.Duration, &inv.Attempts, &inv.ErrorType, &inv.ErrorMessage); err != nil {
		return r, err //nolint:wrapcheck // the callers wrap the scan error
	}
	inv.Time = unstamp(at)
	return r, nil
}

// GetInvocation returns the invocation of the request, whole.
func (s *Service) GetInvocation(
	ctx context.Context,
	requestID string,
) (*contracts.Invocation, error) {
	var (
		inv contracts.Invocation
		seq int64
		at  int64
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT `+detailColumns+` FROM invocations WHERE request_id = ?`, requestID).
			Scan(&seq, &inv.RequestID, &inv.Function, &at, &inv.Source, &inv.Status,
				&inv.Duration, &inv.Attempts, &inv.ErrorType, &inv.ErrorMessage,
				&inv.Payload, &inv.Result, &inv.Log)
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.ErrInvocationNotFound
		}
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	inv.Time = unstamp(at)
	return &inv, nil
}

// ListInvocations returns a page of the invocations f matches, newest
// first.
func (s *Service) ListInvocations(
	ctx context.Context,
	f contracts.InvocationFilter,
	page contracts.PageInput,
) (*contracts.Page[contracts.Invocation], error) {
	before, err := decodeToken(page.Token, listInvocations)
	if err != nil {
		return nil, err
	}
	var (
		where []string
		args  []any
	)
	add := func(cond string, arg any) {
		where = append(where, cond)
		args = append(args, arg)
	}
	if before > 0 {
		add("seq < ?", before)
	}
	if f.Function != "" {
		add("function_name = ?", f.Function)
	}
	if f.Status != "" {
		add("status = ?", f.Status)
	}
	if f.Source != "" {
		add("source = ?", f.Source)
	}
	if f.Since != nil {
		add("started_at >= ?", stamp(*f.Since))
	}
	if f.Until != nil {
		add("started_at <= ?", stamp(*f.Until))
	}
	query := `SELECT ` + summaryColumns + ` FROM invocations`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, page.Size+1)

	var out *contracts.Page[contracts.Invocation]
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		rows, qErr := queryAll(ctx, tx, scanSummary, query, args...)
		if qErr != nil {
			return qErr
		}
		out = paginate(rows, page.Size, listInvocations)
		return nil
	})
	return out, err
}

// DeleteInvocations empties the history.
func (s *Service) DeleteInvocations(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := exec(ctx, tx, `DELETE FROM invocations`)
		return err
	})
}
