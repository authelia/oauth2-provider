// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2/testing/mock"
)

type joinTestKey struct{}

func TestJoinOrBeginTxNested(t *testing.T) {
	ctrl := gomock.NewController(t)

	store := mock.NewMockTransactional(ctrl)

	store.EXPECT().
		BeginTX(gomock.Any()).
		DoAndReturn(func(ctx context.Context) (context.Context, error) {
			return context.WithValue(ctx, joinTestKey{}, "tx"), nil
		}).
		Times(1)

	outer, owned, err := JoinOrBeginTx(t.Context(), store)
	require.NoError(t, err)
	assert.True(t, owned)
	assert.Equal(t, "tx", outer.Value(joinTestKey{}))

	inner, owned, err := JoinOrBeginTx(outer, store)
	require.NoError(t, err)
	assert.False(t, owned)
	assert.Equal(t, outer, inner)
}

func TestJoinOrBeginTxDoesNotJoinMaybeBeginTx(t *testing.T) {
	ctrl := gomock.NewController(t)

	store := mock.NewMockTransactional(ctrl)

	store.EXPECT().
		BeginTX(gomock.Any()).
		DoAndReturn(func(ctx context.Context) (context.Context, error) {
			return ctx, nil
		}).
		Times(2)

	outer, err := MaybeBeginTx(t.Context(), store)
	require.NoError(t, err)

	_, owned, err := JoinOrBeginTx(outer, store)
	require.NoError(t, err)
	assert.True(t, owned)
}

func TestJoinOrBeginTxBeginError(t *testing.T) {
	ctrl := gomock.NewController(t)

	store := mock.NewMockTransactional(ctrl)

	expected := errors.New("begin failed")

	store.EXPECT().BeginTX(gomock.Any()).Return(nil, expected).Times(1)

	ctx, owned, err := JoinOrBeginTx(t.Context(), store)
	require.ErrorIs(t, err, expected)
	assert.False(t, owned)
	assert.Equal(t, t.Context(), ctx)
}

func TestJoinOrBeginTxNotTransactional(t *testing.T) {
	ctx, owned, err := JoinOrBeginTx(t.Context(), NewMemoryStore())
	require.NoError(t, err)
	assert.True(t, owned)
	assert.Equal(t, t.Context(), ctx)

	_, owned, err = JoinOrBeginTx(ctx, NewMemoryStore())
	require.NoError(t, err)
	assert.True(t, owned)
}
