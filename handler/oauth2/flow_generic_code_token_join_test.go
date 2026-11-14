// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

type joinTxKey struct{}

const joinCode = "join-code"

type joinCodeHandler struct {
	ar         oauth2.Requester
	invalidate error
	reads      int
}

func (h *joinCodeHandler) ValidateGrantTypes(_ context.Context, _ oauth2.AccessRequester) error {
	return nil
}

func (h *joinCodeHandler) ValidateCodeAndSession(_ context.Context, _ oauth2.AccessRequester, _ oauth2.Requester, _ string) error {
	return nil
}

func (h *joinCodeHandler) GetCodeAndSession(_ context.Context, _ oauth2.AccessRequester) (string, string, oauth2.Requester, error) {
	h.reads++

	var err error

	if h.reads > 1 {
		err = h.invalidate
	}

	return joinCode, "signature", h.ar, err
}

func (h *joinCodeHandler) UpdateLastChecked(_ context.Context, _ oauth2.AccessRequester, _ oauth2.Requester) error {
	return nil
}

func (h *joinCodeHandler) InvalidateSession(_ context.Context, _ string, _ oauth2.Requester) error {
	return h.invalidate
}

func (h *joinCodeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

func (h *joinCodeHandler) CanHandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) bool {
	return true
}

func (h *joinCodeHandler) DeviceCodeSignature(_ context.Context, code string) (string, error) {
	return code, nil
}

func isJoinTx(ctx any) bool {
	c, ok := ctx.(context.Context)

	return ok && c.Value(joinTxKey{}) == "outer"
}

type joinFixture struct {
	transactional *mock.MockTransactional
	core          *mock.MockCoreStorage
	store         CoreStorage
	code          *joinCodeHandler
	handler       *GenericCodeTokenEndpointHandler
	request       *oauth2.AccessRequest
}

func newJoinFixture(ctrl *gomock.Controller, invalidate error) *joinFixture {
	f := &joinFixture{
		transactional: mock.NewMockTransactional(ctrl),
		core:          mock.NewMockCoreStorage(ctrl),
	}

	f.store = struct {
		storage.Transactional
		CoreStorage
	}{f.transactional, f.core}

	client := &oauth2.DefaultClient{ID: "join-client", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}

	f.code = &joinCodeHandler{
		ar: &oauth2.Request{
			ID:          "join-request",
			Client:      client,
			Session:     &oauth2.DefaultSession{},
			RequestedAt: time.Now().UTC(),
		},
		invalidate: invalidate,
	}

	f.handler = &GenericCodeTokenEndpointHandler{
		CodeTokenEndpointHandler: f.code,
		AccessTokenStrategy:      &hmacshaStrategy,
		RefreshTokenStrategy:     &hmacshaStrategy,
		CoreStorage:              f.store,
		TokenRevocationStorage:   mock.NewMockTokenRevocationStorage(ctrl),
		Config: &oauth2.Config{
			AccessTokenLifespan: time.Minute,
			AudienceStrategy:    oauth2.DefaultAudienceStrategy,
		},
	}

	f.request = &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			Client:      client,
			Session:     &oauth2.DefaultSession{},
			RequestedAt: time.Now().UTC(),
		},
	}

	return f
}

func beginJoinTx(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, joinTxKey{}, "outer"), nil
}

func TestGenericHandlerJoinsOuterTx(t *testing.T) {
	testCases := []struct {
		name       string
		invalidate error
		create     error
		expected   error
	}{
		{name: "ShouldNotCommitOnSuccess"},
		{name: "ShouldNotRollBackOnAWriteError", create: errors.New("write failed"), expected: oauth2.ErrServerError},
		{name: "ShouldNotRevokeOnAReplay", invalidate: oauth2.ErrInvalidatedAuthorizeCode, expected: oauth2.ErrInvalidGrant},
		{name: "ShouldNotRereadOnASerializationFailure", invalidate: oauth2.ErrSerializationFailure, expected: oauth2.ErrServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			f := newJoinFixture(ctrl, tc.invalidate)

			f.transactional.EXPECT().BeginTX(gomock.Any()).DoAndReturn(beginJoinTx).Times(1)

			if tc.invalidate == nil {
				f.core.EXPECT().
					CreateAccessTokenSession(gomock.Cond(isJoinTx), gomock.Any(), gomock.Any()).
					Return(tc.create).
					Times(1)
			}

			outer, owned, err := storage.JoinOrBeginTx(t.Context(), f.store)
			require.NoError(t, err)
			require.True(t, owned)

			err = f.handler.PopulateTokenEndpointResponse(outer, f.request, oauth2.NewAccessResponse())

			if tc.expected == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				require.ErrorIs(t, err, tc.expected)
			}

			assert.Equal(t, 1, f.code.reads)
		})
	}
}

func TestGenericHandlerOwnsItsTx(t *testing.T) {
	ctrl := gomock.NewController(t)

	f := newJoinFixture(ctrl, nil)

	gomock.InOrder(
		f.transactional.EXPECT().BeginTX(gomock.Any()).DoAndReturn(beginJoinTx),
		f.core.EXPECT().CreateAccessTokenSession(gomock.Cond(isJoinTx), gomock.Any(), gomock.Any()).Return(nil),
		f.transactional.EXPECT().Commit(gomock.Cond(isJoinTx)).Return(nil),
	)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.PopulateTokenEndpointResponse(t.Context(), f.request, oauth2.NewAccessResponse())))
}
