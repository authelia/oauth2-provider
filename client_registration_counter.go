// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
)

// ErrClientRegistrationLimitReached is returned by ClientRegistrationCounterStorage.ReserveClientRegistration when the
// count for the key already equals the maximum.
var ErrClientRegistrationLimitReached = errors.New("client registration limit reached")

// ClientRegistrationCounterStorage is an optional storage interface which counts the clients registered per creation
// token key, so a registration policy can cap how many clients one token creates. Entries are keyed per creation token
// and serve no purpose once that token expires; the in-memory store never prunes them, so a persistent implementation
// should expire them no earlier than the token does.
type ClientRegistrationCounterStorage interface {
	// ReserveClientRegistration atomically increments the count for the key, returning
	// ErrClientRegistrationLimitReached without incrementing if the count already equals max.
	ReserveClientRegistration(ctx context.Context, key string, max int64) (err error)

	// ReleaseClientRegistration decrements the count for the key, never below zero.
	ReleaseClientRegistration(ctx context.Context, key string) (err error)
}
