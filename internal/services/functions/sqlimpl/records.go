package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"tule.dev/functions/internal/contracts"
)

// PutFunction stores a new function, failing with ErrFunctionExists when
// one has its name.
func (s *Service) PutFunction(ctx context.Context, fn *contracts.Function) error {
	rec, err := toJSON(fn)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, eErr := exec(ctx, tx,
			`INSERT INTO functions (name, record) VALUES (?, ?) ON CONFLICT (name) DO NOTHING`,
			fn.Name, rec)
		if eErr != nil {
			return eErr
		}
		n, aErr := affected(res)
		if aErr != nil {
			return aErr
		}
		if n == 0 {
			return contracts.ErrFunctionExists
		}
		return nil
	})
}

// GetFunction returns the named function.
func (s *Service) GetFunction(ctx context.Context, name string) (*contracts.Function, error) {
	var fn *contracts.Function
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var gErr error
		fn, gErr = getFunction(ctx, tx, name)
		return gErr
	})
	return fn, err
}

func getFunction(ctx context.Context, tx *sql.Tx, name string) (*contracts.Function, error) {
	var rec string
	err := tx.QueryRowContext(ctx, `SELECT record FROM functions WHERE name = ?`, name).
		Scan(&rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contracts.ErrFunctionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	var fn contracts.Function
	if err = fromJSON(rec, &fn); err != nil {
		return nil, err
	}
	return &fn, nil
}

// UpdateFunction changes the named function with update, in one
// transaction.
func (s *Service) UpdateFunction(
	ctx context.Context,
	name string,
	update func(*contracts.Function) error,
) (*contracts.Function, error) {
	var fn *contracts.Function
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var gErr error
		if fn, gErr = getFunction(ctx, tx, name); gErr != nil {
			return gErr
		}
		if uErr := update(fn); uErr != nil {
			return uErr
		}
		rec, jErr := toJSON(fn)
		if jErr != nil {
			return jErr
		}
		_, eErr := exec(ctx, tx, `UPDATE functions SET record = ? WHERE name = ?`, rec, name)
		return eErr
	})
	if err != nil {
		return nil, err
	}
	return fn, nil
}

// DeleteFunction deletes the named function.
func (s *Service) DeleteFunction(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := exec(ctx, tx, `DELETE FROM functions WHERE name = ?`, name)
		if err != nil {
			return err
		}
		n, err := affected(res)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrFunctionNotFound
		}
		return nil
	})
}

// ListFunctions returns a page of the functions, in the order they were
// created.
func (s *Service) ListFunctions(
	ctx context.Context,
	page contracts.PageInput,
) (*contracts.Page[contracts.Function], error) {
	after, err := decodeToken(page.Token, listFunctions)
	if err != nil {
		return nil, err
	}
	var out *contracts.Page[contracts.Function]
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		rows, qErr := queryAll(ctx, tx, scanRecord[contracts.Function],
			`SELECT seq, record FROM functions WHERE seq > ? ORDER BY seq LIMIT ?`,
			after, page.Size+1)
		if qErr != nil {
			return qErr
		}
		out = paginate(rows, page.Size, listFunctions)
		return nil
	})
	return out, err
}

// AllFunctions returns every function.
func (s *Service) AllFunctions(ctx context.Context) ([]contracts.Function, error) {
	var out []contracts.Function
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, qErr := queryAll(ctx, tx, scanRecord[contracts.Function],
			`SELECT seq, record FROM functions ORDER BY seq`)
		for _, r := range rows {
			out = append(out, r.item)
		}
		return qErr
	})
	return out, err
}

func scanRecord[T any](row scanner) (rowed[T], error) {
	var (
		r   rowed[T]
		rec string
	)
	if err := row.Scan(&r.seq, &rec); err != nil {
		return r, err //nolint:wrapcheck // queryAll wraps the scan error
	}
	return r, fromJSON(rec, &r.item)
}

// PutMapping stores a new mapping.
func (s *Service) PutMapping(ctx context.Context, m *contracts.Mapping) error {
	rec, err := toJSON(m)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, eErr := exec(ctx, tx,
			`INSERT INTO mappings (uuid, function_name, event_source_arn, record)
			 VALUES (?, ?, ?, ?)`, m.UUID, m.FunctionName, m.EventSourceARN, rec)
		return eErr
	})
}

// GetMapping returns the mapping with the given UUID.
func (s *Service) GetMapping(ctx context.Context, uuid string) (*contracts.Mapping, error) {
	var m *contracts.Mapping
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var gErr error
		m, gErr = getMapping(ctx, tx, uuid)
		return gErr
	})
	return m, err
}

func getMapping(ctx context.Context, tx *sql.Tx, uuid string) (*contracts.Mapping, error) {
	var rec string
	err := tx.QueryRowContext(ctx, `SELECT record FROM mappings WHERE uuid = ?`, uuid).
		Scan(&rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contracts.ErrMappingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	var m contracts.Mapping
	if err = fromJSON(rec, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// UpdateMapping changes the mapping with update, in one transaction.
func (s *Service) UpdateMapping(
	ctx context.Context,
	uuid string,
	update func(*contracts.Mapping) error,
) (*contracts.Mapping, error) {
	var m *contracts.Mapping
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var gErr error
		if m, gErr = getMapping(ctx, tx, uuid); gErr != nil {
			return gErr
		}
		if uErr := update(m); uErr != nil {
			return uErr
		}
		rec, jErr := toJSON(m)
		if jErr != nil {
			return jErr
		}
		_, eErr := exec(ctx, tx,
			`UPDATE mappings SET record = ?, function_name = ?, event_source_arn = ?
			 WHERE uuid = ?`, rec, m.FunctionName, m.EventSourceARN, uuid)
		return eErr
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// DeleteMapping deletes the mapping with the given UUID.
func (s *Service) DeleteMapping(ctx context.Context, uuid string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := exec(ctx, tx, `DELETE FROM mappings WHERE uuid = ?`, uuid)
		if err != nil {
			return err
		}
		n, err := affected(res)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrMappingNotFound
		}
		return nil
	})
}

// ListMappings returns a page of the mappings f matches, in the order they
// were created.
func (s *Service) ListMappings(
	ctx context.Context,
	f contracts.MappingFilter,
	page contracts.PageInput,
) (*contracts.Page[contracts.Mapping], error) {
	after, err := decodeToken(page.Token, listMappings)
	if err != nil {
		return nil, err
	}
	where := []string{"seq > ?"}
	args := []any{after}
	if f.FunctionName != "" {
		where = append(where, "function_name = ?")
		args = append(args, f.FunctionName)
	}
	if f.EventSourceARN != "" {
		where = append(where, "event_source_arn = ?")
		args = append(args, f.EventSourceARN)
	}
	args = append(args, page.Size+1)
	var out *contracts.Page[contracts.Mapping]
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		rows, qErr := queryAll(ctx, tx, scanRecord[contracts.Mapping],
			`SELECT seq, record FROM mappings WHERE `+strings.Join(where, " AND ")+
				` ORDER BY seq LIMIT ?`, args...)
		if qErr != nil {
			return qErr
		}
		out = paginate(rows, page.Size, listMappings)
		return nil
	})
	return out, err
}

// AllMappings returns every mapping.
func (s *Service) AllMappings(ctx context.Context) ([]contracts.Mapping, error) {
	var out []contracts.Mapping
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, qErr := queryAll(ctx, tx, scanRecord[contracts.Mapping],
			`SELECT seq, record FROM mappings ORDER BY seq`)
		for _, r := range rows {
			out = append(out, r.item)
		}
		return qErr
	})
	return out, err
}
