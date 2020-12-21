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
	"sync/atomic"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type (
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
		count int64
		id    string
	}

	txCommitErr struct {
		err error
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
func (b *Backend) Transact(ctx context.Context, handler TxHandler) (err error) {
	ctx, ref, err := b.txRef(ctx)
	if err != nil {
		return
	}

	log := api.Log(ctx)

	log.Debugf("database tx %s begin", ref.id)

	defer func() {
		if p := recover(); p != nil {
			ref.Rollback()
			panic(p)
		}

		if atomic.AddInt64(&ref.count, -1) > 0 {
			return
		}

		var t txCommitErr

		if errors.As(err, &t) {
			err = nil
		}

		if err != nil {
			ref.Rollback()
			log.Debugf("database tx %s rollback", ref.id)
		} else if err = ref.Commit(); err == nil {
			log.Debugf("database tx %s commit succeeded", ref.id)
			err = t.err
		} else {
			log.Errorf("database tx %s commit failed: %s", ref.id, err)
		}
	}()

	err = handler(ctx, ref)

	return
}

func (b *Backend) txRef(ctx context.Context) (context.Context, *txRef, error) {
	tmp := ctx.Value(contextKeyTx)
	if ref, ok := tmp.(*txRef); ok {
		atomic.AddInt64(&ref.count, 1)
		return ctx, ref, nil
	}

	tx, err := b.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	ref := &txRef{tx, 1, uuid.Must(uuid.NewRandom()).String()}

	ctx = context.WithValue(ctx, contextKeyTx, ref)

	return ctx, ref, err
}

// DB returns a transaction from the context if it exists or the db
func (b *Backend) DB(ctx context.Context) DB {
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
