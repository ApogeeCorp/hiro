/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://github.com/ModelRocket/hiro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package hiro

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mr-tron/base58/base58"
	migrate "github.com/rubenv/sql-migrate"
)

type (
	// DBController is the db interface
	DBController interface {
		// Starts a database transaction
		Transact(ctx context.Context, handler TxHandler, ignore ...error) error

		// Gets a handle to the database
		DB(ctx context.Context) DB
	}

	// DB is an aggregate interface for sqlx transactions
	DB interface {
		sqlx.Ext
		sqlx.ExtContext
		SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
		GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	}

	// TxHandler is a db transaction handler
	TxHandler func(context.Context, DB) error

	txRef struct {
		*sqlx.Tx
		count  int64
		id     string
		ignore []error
		stack  []string
	}

	txCommitErr struct {
		err error
	}

	// Migration is a db migration
	Migration struct {
		*migrate.AssetMigrationSource
		Schema string
	}
)

var (
	contextKeyTx contextKey = "hiro:context:tx"
)

// ErrTxCommit is used to return an error from within a tx handler but still commit
func ErrTxCommit(err error) error {
	return txCommitErr{err}
}

func (e txCommitErr) Error() string {
	return e.err.Error()
}

// Transact starts a db transaction, adds it to the context and calls the handler
func (b *Hiro) Transact(ctx context.Context, handler TxHandler, ignore ...error) (err error) {
	ctx, ref, err := b.txRef(ctx, ignore...)
	if err != nil {
		return
	}

	log := Log(ctx)

	if ref.count == 1 {
		log.Debugf("database tx %s begin", ref.id)
	}

	defer func() {
		if p := recover(); p != nil {
			ref.Rollback()
			panic(p)
		}

		var t txCommitErr

		if errors.As(err, &t) {
			err = nil
		}

		if err != nil {
			// capture the internally ignored error
			var txErr error

			for _, e := range ref.ignore {
				if errors.Is(err, e) {
					txErr = err
					n := len(ref.stack) - 1
					id := ref.stack[n]
					ref.stack = ref.stack[:n]

					if _, err = ref.ExecContext(ctx, fmt.Sprintf(`ROLLBACK TO SAVEPOINT "%s";`, id)); err != nil {
						txErr = nil
					}
					break
				}
			}

			if txErr != nil {
				err = txErr
			} else if err != nil {
				ref.Rollback()
				log.Debugf("database tx %s rollback", ref.id)
			}

			err = ParseSQLError(err)
		}

		if atomic.AddInt64(&ref.count, -1) > 0 || err != nil {
			return
		}

		if err = ref.Commit(); err == nil {
			log.Debugf("database tx %s commit succeeded", ref.id)
			err = t.err
		} else {
			log.Errorf("database tx %s commit failed: %s", ref.id, err)
		}
	}()

	err = handler(ctx, ref)

	return
}

func (b *Hiro) txRef(ctx context.Context, ignore ...error) (context.Context, *txRef, error) {
	tmp := ctx.Value(contextKeyTx)
	if ref, ok := tmp.(*txRef); ok {
		atomic.AddInt64(&ref.count, 1)

		if len(ref.ignore) > 0 {
			id := uuid.Must(uuid.NewRandom())
			ref.stack = append(ref.stack, base58.Encode(id[:]))
			n := len(ref.stack) - 1
			if _, err := ref.ExecContext(ctx, fmt.Sprintf(`SAVEPOINT "%s";`, ref.stack[n])); err != nil {
				return nil, nil, err
			}
		}

		return ctx, ref, nil
	}

	tx, err := b.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	id := uuid.Must(uuid.NewRandom())
	ref := &txRef{
		Tx:     tx,
		count:  1,
		id:     base58.Encode(id[:]),
		ignore: ignore,
		stack:  make([]string, 0),
	}

	ctx = context.WithValue(ctx, contextKeyTx, ref)

	return ctx, ref, err
}

// DB returns a transaction from the context if it exists or the db
func (b *Hiro) DB(ctx context.Context) DB {
	tx := ctx.Value(contextKeyTx)
	if ref, ok := tx.(*txRef); ok {
		return ref
	}
	return b.db
}

// IsTransaction returns true of the DB interface is a transaction
func IsTransaction(db DB) bool {
	_, ok := db.(*txRef)
	return ok
}
