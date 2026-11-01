// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

// Transactional represents a storage provider that has support for transactions should implement this interface to ensure atomicity for certain flows
// that require transactional semantics. Fosite will call these methods (when atomicity is required) if and only if the storage
// provider has implemented `Transactional`. It is expected that the storage provider will examine context for an existing transaction
// each time a database operation is to be performed.
//
// An implementation of `BeginTX` should attempt to initiate a new transaction and store that under a unique key
// in the context that can be accessible by `Commit` and `Rollback`. The "transactional aware" context will then be
// returned for further propagation, eventually to be consumed by `Commit` or `Rollback` to finish the transaction.
//
// Implementations for `Commit` & `Rollback` should look for the transaction object inside the supplied context using the same
// key used by `BeginTX`. If these methods have been called, it is expected that a txn object should be available in the provided
// context.
//
// A store MUST implement this interface for the revocation of a replayed authorization code, device code or refresh token
// to be complete, as RFC 6749 Section 4.1.2 and RFC 9700 Section 4.14.2 describe. The handlers invalidate or rotate the
// token before they write the tokens which replace it. Without a transaction a replay in that window is refused but revokes
// nothing, and the tokens written afterwards stay live. Within a transaction, an invalidation or rotation which has not
// been committed MUST NOT be visible to another request, and a concurrent update of the same token MUST either wait for it
// or fail with oauth2.ErrSerializationFailure.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
type Transactional interface {
	BeginTX(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// MaybeBeginTx is a helper function that can be used to initiate a transaction if the supplied storage
// implements the `Transactional` interface.
func MaybeBeginTx(ctx context.Context, storage any) (context.Context, error) {
	// the type assertion checks whether the dynamic type of `storage` implements `Transactional`
	txnStorage, transactional := storage.(Transactional)
	if transactional {
		return txnStorage.BeginTX(ctx)
	} else {
		return ctx, nil
	}
}

// MaybeCommitTx is a helper function that can be used to commit a transaction if the supplied storage
// implements the `Transactional` interface.
func MaybeCommitTx(ctx context.Context, storage any) error {
	txnStorage, transactional := storage.(Transactional)
	if transactional {
		return txnStorage.Commit(ctx)
	} else {
		return nil
	}
}

// MaybeRollbackTx is a helper function that can be used to rollback a transaction if the supplied storage
// implements the `Transactional` interface.
func MaybeRollbackTx(ctx context.Context, storage any) error {
	txnStorage, transactional := storage.(Transactional)
	if transactional {
		return txnStorage.Rollback(ctx)
	} else {
		return nil
	}
}
