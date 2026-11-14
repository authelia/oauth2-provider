// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package transaction joins and finishes storage transactions for packages which cannot import the storage package.
package transaction

import (
	"context"
)

// Transactional has the method set of storage.Transactional.
type Transactional interface {
	BeginTX(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type joinableKey struct{}

// JoinOrBegin implements storage.JoinOrBeginTx, which documents it.
func JoinOrBegin(ctx context.Context, storage any) (txCtx context.Context, owned bool, err error) {
	txnStorage, transactional := storage.(Transactional)
	if !transactional {
		return ctx, true, nil
	}

	if joinable, _ := ctx.Value(joinableKey{}).(bool); joinable {
		return ctx, false, nil
	}

	if txCtx, err = txnStorage.BeginTX(ctx); err != nil {
		return ctx, false, err
	}

	return context.WithValue(txCtx, joinableKey{}, true), true, nil
}

// Commit commits the transaction of ctx when storage implements Transactional.
func Commit(ctx context.Context, storage any) error {
	if txnStorage, transactional := storage.(Transactional); transactional {
		return txnStorage.Commit(ctx)
	}

	return nil
}

// Rollback rolls back the transaction of ctx when storage implements Transactional.
func Rollback(ctx context.Context, storage any) error {
	if txnStorage, transactional := storage.(Transactional); transactional {
		return txnStorage.Rollback(ctx)
	}

	return nil
}
