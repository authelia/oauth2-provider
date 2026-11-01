// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestExchangeTokenLookupError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected error
	}{
		{name: "ShouldAnswerServerErrorForAStorageFailure", err: errors.New("connection refused"), expected: oauth2.ErrServerError},
		{name: "ShouldAnswerServerErrorForASerializationFailure", err: oauth2.ErrSerializationFailure, expected: oauth2.ErrServerError},
		{name: "ShouldAnswerServerErrorForAServerSideRFCError", err: oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrServerError},
		{name: "ShouldAnswerInvalidRequestForAnUnknownToken", err: oauth2.ErrNotFound, expected: oauth2.ErrInvalidRequest},
		{name: "ShouldAnswerInvalidRequestForAWrappedUnknownToken", err: errorsx.WithStack(oauth2.ErrNotFound), expected: oauth2.ErrInvalidRequest},
		{name: "ShouldAnswerInvalidRequestForARejection", err: oauth2.ErrTokenSignatureMismatch, expected: oauth2.ErrInvalidRequest},
	}

	roles := []struct {
		name string
		form string
		kind string
	}{
		{name: "Subject", form: consts.FormParameterSubjectToken, kind: consts.FormParameterSubjectTokenType},
		{name: "Actor", form: consts.FormParameterActorToken, kind: consts.FormParameterActorTokenType},
	}

	types := []struct {
		name  string
		kind  string
		store func(store rfc8693ExchangeStore, err error) *failingLookupStore
	}{
		{
			name: "AccessToken",
			kind: consts.TokenTypeRFC8693AccessToken,
			store: func(store rfc8693ExchangeStore, err error) *failingLookupStore {
				return &failingLookupStore{rfc8693ExchangeStore: store, access: err}
			},
		},
		{
			name: "RefreshToken",
			kind: consts.TokenTypeRFC8693RefreshToken,
			store: func(store rfc8693ExchangeStore, err error) *failingLookupStore {
				return &failingLookupStore{rfc8693ExchangeStore: store, refresh: err}
			},
		},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tt := range types {
			for _, role := range roles {
				for _, tc := range testCases {
					t.Run(sc.name+"/"+tt.name+"/"+role.name+"/"+tc.name, func(t *testing.T) {
						config, strategy := newBindingExchangeConfig()
						config.RefreshTokenScopes = []string{}
						config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

						store := tt.store(sc.newStore(), tc.err)

						request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, "unused", consts.TokenTypeRFC8693AccessToken)
						request.Form.Set(role.form, "token")
						request.Form.Set(role.kind, tt.kind)

						var err error

						if tt.kind == consts.TokenTypeRFC8693AccessToken {
							err = newLifetimeAccessTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)
						} else {
							request.Form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693RefreshToken)
							request.Form.Set(role.kind, tt.kind)
							err = newLifetimeRefreshTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)
						}

						assert.ErrorIs(t, err, tc.expected)

						if errors.Is(tc.expected, oauth2.ErrServerError) {
							assert.NotErrorIs(t, err, oauth2.ErrInvalidRequest)
						}
					})
				}
			}
		}
	}
}

func TestCustomJWTMarkError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected error
	}{
		{name: "ShouldAnswerInvalidRequestForAKnownJTI", err: oauth2.ErrJTIKnown, expected: oauth2.ErrInvalidRequest},
		{name: "ShouldAnswerInvalidRequestForAWrappedKnownJTI", err: errorsx.WithStack(oauth2.ErrJTIKnown), expected: oauth2.ErrInvalidRequest},
		{name: "ShouldAnswerServerErrorForAStorageFailure", err: errors.New("connection refused"), expected: oauth2.ErrServerError},
		{name: "ShouldAnswerServerErrorForASerializationFailure", err: oauth2.ErrSerializationFailure, expected: oauth2.ErrServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, true)
			f.grant.Storage = &failingJTIStore{err: tc.err}

			request := f.request(url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
			})

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))

			assert.ErrorIs(t, f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), tc.expected)
		})
	}
}

func TestCustomJWTSubjectLookupError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected error
		hint     string
	}{
		{name: "ShouldAnswerServerErrorForAStorageFailure", err: errors.New("connection refused"), expected: oauth2.ErrServerError},
		{name: "ShouldAnswerServerErrorForASerializationFailure", err: oauth2.ErrSerializationFailure, expected: oauth2.ErrServerError},
		{name: "ShouldAnswerServerErrorForAServerSideRFCError", err: oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrServerError},
		{name: "ShouldAnswerInvalidRequestForAnUnknownSubject", err: oauth2.ErrNotFound, expected: oauth2.ErrInvalidRequest, hint: "The 'subject_token' does not identify a subject."},
		{name: "ShouldKeepARejection", err: oauth2.ErrInvalidRequest.WithHint("No subject found."), expected: oauth2.ErrInvalidRequest, hint: "No subject found."},
		{name: "ShouldAnswerServerErrorForADecodeError", err: base64.CorruptInputError(1), expected: oauth2.ErrServerError},
		{name: "ShouldKeepAServerErrorWrappingAnUnknownSubject", err: oauth2.ErrServerError.WithWrap(oauth2.ErrNotFound), expected: oauth2.ErrServerError},
		{name: "ShouldKeepARefusalWrappingAnUnknownSubject", err: oauth2.ErrAccessDenied.WithWrap(oauth2.ErrNotFound), expected: oauth2.ErrAccessDenied},
		{name: "ShouldAnswerInvalidRequestForAWrappedUnknownSubject", err: errorsx.WithStack(oauth2.ErrNotFound), expected: oauth2.ErrInvalidRequest, hint: "The 'subject_token' does not identify a subject."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, false)
			f.custom.Storage = &failingSubjectStore{MemoryStore: f.store, err: tc.err}

			err := f.custom.HandleTokenEndpointRequest(t.Context(), f.request(url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
			}))

			require.ErrorIs(t, err, tc.expected)
			assert.Equal(t, tc.expected.(*oauth2.RFC6749Error).ErrorField, oauth2.ErrorToRFC6749Error(err).ErrorField)

			if tc.hint != "" {
				assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
			}
		})
	}
}

type failingSubjectStore struct {
	*storage.MemoryStore

	err error
}

func (s *failingSubjectStore) GetSubjectForTokenExchange(_ context.Context, _ oauth2.Requester, _ map[string]any) (string, error) {
	return "", s.err
}

type failingLookupStore struct {
	rfc8693ExchangeStore

	access, refresh error
}

func (s *failingLookupStore) GetAccessTokenSession(_ context.Context, _ string, _ oauth2.Session) (oauth2.Requester, error) {
	return nil, s.access
}

func (s *failingLookupStore) GetRefreshTokenSession(_ context.Context, _ string, _ oauth2.Session) (oauth2.Requester, error) {
	return nil, s.refresh
}

type failingJTIStore struct {
	err error
}

func (s *failingJTIStore) SetTokenExchangeCustomJWT(_ context.Context, _, _ string, _ time.Time) error {
	return s.err
}
