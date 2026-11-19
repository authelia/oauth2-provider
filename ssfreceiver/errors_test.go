// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetError(t *testing.T) {
	t.Run("ShouldImplementError", func(t *testing.T) {
		var err error = &SetError{Code: "access_denied", Description: "The event was refused."}

		assert.EqualError(t, err, "access_denied: The event was refused.")
	})

	t.Run("ShouldOmitEmptyDescription", func(t *testing.T) {
		assert.EqualError(t, &SetError{Code: "invalid_request"}, "invalid_request")
	})

	t.Run("ShouldMatchThroughWrapping", func(t *testing.T) {
		err := fmt.Errorf("handler: %w", &SetError{Code: "invalid_key"})

		var target *SetError

		require.True(t, errors.As(err, &target))
		assert.Equal(t, "invalid_key", target.Code)
	})

	t.Run("ShouldHandleNil", func(t *testing.T) {
		var err *SetError

		assert.Equal(t, "", err.Error())
	})
}

func TestWrapError(t *testing.T) {
	sentinel := errors.New("ssfreceiver: the outer one")

	t.Run("ShouldHaveThePackagePrefixOnce", func(t *testing.T) {
		err := wrapError(sentinel.Error()+": the 'iss'", ErrIssuerMismatch, sentinel)

		assert.EqualError(t, err, "ssfreceiver: the outer one: the 'iss': the 'issuer' is not the requested issuer")
		require.ErrorIs(t, err, sentinel)
		require.ErrorIs(t, err, ErrIssuerMismatch)
	})

	t.Run("ShouldKeepACauseWithoutThePrefix", func(t *testing.T) {
		cause := &SetError{Code: "invalid_key"}

		err := wrapError(sentinel.Error(), fmt.Errorf("handler: %w", cause))

		assert.EqualError(t, err, "ssfreceiver: the outer one: handler: invalid_key")
		assert.NotErrorIs(t, err, sentinel)

		var target *SetError

		require.ErrorAs(t, err, &target)
		assert.Same(t, cause, target)
	})
}
