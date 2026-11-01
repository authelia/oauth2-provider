// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestAuthorizeCodeSerializationFailure(t *testing.T) {
	testCases := []struct {
		name     string
		commit   bool
		winner   bool
		expected error
	}{
		{name: "ShouldRevokeWhenAnotherRequestInvalidatedTheCode", winner: true, expected: oauth2.ErrInvalidGrant},
		{name: "ShouldRevokeWhenTheCommitFailsAfterAnotherRequestInvalidatedTheCode", commit: true, winner: true, expected: oauth2.ErrInvalidGrant},
		{name: "ShouldAnswerAServerErrorForContention", expected: oauth2.ErrServerError},
	}

	for _, s := range serializationFailureStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := &serializationFailureStore{serializationStorage: s.new(), commit: tc.commit}
				strategy := &hmacshaStrategy

				client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}

				handler := AuthorizeExplicitGrantHandler{
					CoreStorage:            store,
					TokenRevocationStorage: store,
					AuthorizeCodeStrategy:  strategy,
					AccessTokenStrategy:    strategy,
					RefreshTokenStrategy:   strategy,
					Config: &oauth2.Config{
						ScopeStrategy:         oauth2.HierarchicScopeStrategy,
						AudienceStrategy:      oauth2.DefaultAudienceStrategy,
						AccessTokenLifespan:   time.Minute,
						AuthorizeCodeLifespan: time.Minute,
					},
				}

				code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				authorize := &oauth2.AuthorizeRequest{
					Request: oauth2.Request{
						ID:           "req-id",
						Client:       client,
						Form:         url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
						GrantedScope: oauth2.Arguments{"foo"},
						Session:      &oauth2.DefaultSession{},
						RequestedAt:  time.Now().UTC(),
					},
				}

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, authorize))

				if tc.winner {
					store.failure = func(ctx context.Context) {
						if !tc.commit {
							require.NoError(t, store.serializationStorage.InvalidateAuthorizeCodeSession(ctx, signature))
						}

						require.NoError(t, store.CreateAccessTokenSession(ctx, "winner-at", authorize))
						require.NoError(t, store.CreateRefreshTokenSession(ctx, "winner-rt", "winner-at", authorize))
					}
				}

				newRequest := func() *oauth2.AccessRequest {
					return &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
						Request: oauth2.Request{
							Client: client,
							Form: url.Values{
								consts.FormParameterAuthorizationCode: {code},
								consts.FormParameterRedirectURI:       {"https://client.example.com/cb"},
							},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					}
				}

				request := newRequest()

				require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

				store.armed = true

				err = handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())
				require.ErrorIs(t, err, tc.expected)

				if tc.winner {
					_, err = store.GetAccessTokenSession(t.Context(), "winner-at", nil)
					assert.ErrorIs(t, err, oauth2.ErrNotFound)

					_, err = store.GetRefreshTokenSession(t.Context(), "winner-rt", nil)
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

					return
				}

				retry := newRequest()

				require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), retry))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), retry, oauth2.NewAccessResponse())))
			})
		}
	}
}

func TestRefreshTokenSerializationFailure(t *testing.T) {
	testCases := []struct {
		name     string
		commit   bool
		winner   bool
		expected error
	}{
		{name: "ShouldRevokeWhenAnotherRequestRotatedTheToken", winner: true, expected: oauth2.ErrInvalidGrant},
		{name: "ShouldRevokeWhenTheCommitFailsAfterAnotherRequestRotatedTheToken", commit: true, winner: true, expected: oauth2.ErrInvalidGrant},
		{name: "ShouldAnswerInvalidRequestForContention", expected: oauth2.ErrInvalidRequest},
	}

	for _, s := range serializationFailureStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := &serializationFailureStore{serializationStorage: s.new(), commit: tc.commit}
				strategy := &hmacshaStrategy

				client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOffline}}

				original := &oauth2.Request{
					ID:           "grant",
					Client:       client,
					GrantedScope: oauth2.Arguments{consts.ScopeOffline},
					Session:      &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}},
					RequestedAt:  time.Now().UTC(),
				}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original))

				handler := &RefreshTokenGrantHandler{
					TokenRevocationStorage: store,
					AccessTokenStrategy:    strategy,
					RefreshTokenStrategy:   strategy,
					Config: &oauth2.Config{
						AccessTokenLifespan:  time.Hour,
						RefreshTokenLifespan: time.Hour,
						ScopeStrategy:        oauth2.HierarchicScopeStrategy,
						AudienceStrategy:     oauth2.DefaultAudienceStrategy,
						RefreshTokenScopes:   []string{consts.ScopeOffline},
					},
				}

				if tc.winner {
					store.failure = func(ctx context.Context) {
						if !tc.commit {
							require.NoError(t, store.serializationStorage.RotateRefreshToken(ctx, original.ID, signature))
						}

						require.NoError(t, store.CreateAccessTokenSession(ctx, "winner-at", original))
						require.NoError(t, store.CreateRefreshTokenSession(ctx, "winner-rt", "winner-at", original))
					}
				}

				newRequest := func() *oauth2.AccessRequest {
					request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
					request.Client = client
					request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
					request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

					return request
				}

				request := newRequest()

				require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

				store.armed = true

				err = handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())
				require.ErrorIs(t, err, tc.expected)

				if tc.winner {
					_, err = store.GetAccessTokenSession(t.Context(), "winner-at", nil)
					assert.ErrorIs(t, err, oauth2.ErrNotFound)

					_, err = store.GetRefreshTokenSession(t.Context(), "winner-rt", nil)
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

					return
				}

				_, err = store.GetRefreshTokenSession(t.Context(), signature, nil)
				require.NoError(t, err)

				retry := newRequest()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), retry)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), retry, oauth2.NewAccessResponse())))
			})
		}
	}
}

func TestSerializationFailureRereadsAfterRollback(t *testing.T) {
	stages := []struct {
		name   string
		commit bool
	}{
		{name: "Write"},
		{name: "Commit", commit: true},
	}

	outcomes := []struct {
		name   string
		winner bool
	}{
		{name: "AnotherRequestWon", winner: true},
		{name: "Contention"},
	}

	for _, s := range serializationFailureStores() {
		for _, stage := range stages {
			for _, outcome := range outcomes {
				t.Run(s.name+"/AuthorizeCode/"+stage.name+"/"+outcome.name, func(t *testing.T) {
					store := &transactionalFailureStore{serializationStorage: s.new(), commit: stage.commit}
					strategy := &hmacshaStrategy

					client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}

					handler := AuthorizeExplicitGrantHandler{
						CoreStorage:            store,
						TokenRevocationStorage: store,
						AuthorizeCodeStrategy:  strategy,
						AccessTokenStrategy:    strategy,
						RefreshTokenStrategy:   strategy,
						Config: &oauth2.Config{
							ScopeStrategy:         oauth2.HierarchicScopeStrategy,
							AudienceStrategy:      oauth2.DefaultAudienceStrategy,
							AccessTokenLifespan:   time.Minute,
							AuthorizeCodeLifespan: time.Minute,
						},
					}

					code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
					require.NoError(t, err)

					authorize := &oauth2.AuthorizeRequest{
						Request: oauth2.Request{
							ID:           "req-id",
							Client:       client,
							Form:         url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					}

					require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, authorize))

					if outcome.winner {
						store.competing = func(ctx context.Context) {
							require.NoError(t, store.serializationStorage.InvalidateAuthorizeCodeSession(ctx, signature))
							require.NoError(t, store.serializationStorage.CreateAccessTokenSession(ctx, "winner-at", authorize))
							require.NoError(t, store.serializationStorage.CreateRefreshTokenSession(ctx, "winner-rt", "winner-at", authorize))
						}
					}

					newRequest := func() *oauth2.AccessRequest {
						return &oauth2.AccessRequest{
							GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
							Request: oauth2.Request{
								Client: client,
								Form: url.Values{
									consts.FormParameterAuthorizationCode: {code},
									consts.FormParameterRedirectURI:       {"https://client.example.com/cb"},
								},
								Session:     &oauth2.DefaultSession{},
								RequestedAt: time.Now().UTC(),
							},
						}
					}

					request := newRequest()

					require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

					store.armed = true

					err = handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

					assert.Zero(t, store.committed)

					if outcome.winner {
						require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

						_, err = store.GetAccessTokenSession(t.Context(), "winner-at", nil)
						assert.ErrorIs(t, err, oauth2.ErrNotFound)

						_, err = store.serializationStorage.GetRefreshTokenSession(t.Context(), "winner-rt", nil)
						assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

						return
					}

					require.ErrorIs(t, err, oauth2.ErrServerError)

					retry := newRequest()

					require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), retry))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), retry, oauth2.NewAccessResponse())))
					assert.NotZero(t, store.committed)
				})

				t.Run(s.name+"/RefreshToken/"+stage.name+"/"+outcome.name, func(t *testing.T) {
					store := &transactionalFailureStore{serializationStorage: s.new(), commit: stage.commit}
					strategy := &hmacshaStrategy

					client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOffline}}

					original := &oauth2.Request{
						ID:           "grant",
						Client:       client,
						GrantedScope: oauth2.Arguments{consts.ScopeOffline},
						Session:      &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}},
						RequestedAt:  time.Now().UTC(),
					}

					token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
					require.NoError(t, err)
					require.NoError(t, store.serializationStorage.CreateRefreshTokenSession(t.Context(), signature, "", original))

					handler := &RefreshTokenGrantHandler{
						TokenRevocationStorage: store,
						AccessTokenStrategy:    strategy,
						RefreshTokenStrategy:   strategy,
						Config: &oauth2.Config{
							AccessTokenLifespan:  time.Hour,
							RefreshTokenLifespan: time.Hour,
							ScopeStrategy:        oauth2.HierarchicScopeStrategy,
							AudienceStrategy:     oauth2.DefaultAudienceStrategy,
							RefreshTokenScopes:   []string{consts.ScopeOffline},
						},
					}

					if outcome.winner {
						store.competing = func(ctx context.Context) {
							require.NoError(t, store.serializationStorage.RotateRefreshToken(ctx, original.ID, signature))
							require.NoError(t, store.serializationStorage.CreateAccessTokenSession(ctx, "winner-at", original))
							require.NoError(t, store.serializationStorage.CreateRefreshTokenSession(ctx, "winner-rt", "winner-at", original))
						}
					}

					newRequest := func() *oauth2.AccessRequest {
						request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
						request.Client = client
						request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

						return request
					}

					request := newRequest()

					require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

					store.armed = true

					err = handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

					assert.Zero(t, store.committed)

					if outcome.winner {
						require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

						_, err = store.GetAccessTokenSession(t.Context(), "winner-at", nil)
						assert.ErrorIs(t, err, oauth2.ErrNotFound)

						_, err = store.serializationStorage.GetRefreshTokenSession(t.Context(), "winner-rt", nil)
						assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

						return
					}

					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

					retry := newRequest()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), retry)))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), retry, oauth2.NewAccessResponse())))
					assert.NotZero(t, store.committed)
				})
			}
		}
	}
}

func serializationFailureStores() []struct {
	name string
	new  func() serializationStorage
} {
	return []struct {
		name string
		new  func() serializationStorage
	}{
		{"MemoryStore", func() serializationStorage { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() serializationStorage { return storage.NewHydratingMemoryStore() }},
	}
}

type serializationStorage interface {
	CoreStorage
	TokenRevocationStorage
}

type serializationFailureStore struct {
	serializationStorage

	commit  bool
	armed   bool
	failure func(ctx context.Context)
}

func (s *serializationFailureStore) fail(ctx context.Context) error {
	s.armed = false

	if s.failure != nil {
		s.failure(ctx)
	}

	return oauth2.ErrSerializationFailure
}

func (s *serializationFailureStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	if s.armed && !s.commit {
		return s.fail(ctx)
	}

	return s.serializationStorage.InvalidateAuthorizeCodeSession(ctx, signature)
}

func (s *serializationFailureStore) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	if s.armed && !s.commit {
		return s.fail(ctx)
	}

	return s.serializationStorage.RotateRefreshToken(ctx, requestID, signature)
}

func (s *serializationFailureStore) BeginTX(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (s *serializationFailureStore) Commit(ctx context.Context) error {
	if s.armed && s.commit {
		return s.fail(ctx)
	}

	return nil
}

func (s *serializationFailureStore) Rollback(_ context.Context) error {
	return nil
}

type transactionalFailureKey struct{}

type transactionalFailure struct {
	writes []func(ctx context.Context) error
	closed bool
}

type transactionalFailureStore struct {
	serializationStorage

	commit    bool
	armed     bool
	committed int
	competing func(ctx context.Context)
}

func (s *transactionalFailureStore) transaction(ctx context.Context) *transactionalFailure {
	tx, _ := ctx.Value(transactionalFailureKey{}).(*transactionalFailure)

	return tx
}

func (s *transactionalFailureStore) usable(ctx context.Context) error {
	if tx := s.transaction(ctx); tx != nil && tx.closed {
		return errors.New("the transaction has already been committed or rolled back")
	}

	return nil
}

func (s *transactionalFailureStore) write(ctx context.Context, write func(ctx context.Context) error) error {
	if err := s.usable(ctx); err != nil {
		return err
	}

	if tx := s.transaction(ctx); tx != nil {
		tx.writes = append(tx.writes, write)

		return nil
	}

	return write(ctx)
}

func (s *transactionalFailureStore) BeginTX(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, transactionalFailureKey{}, &transactionalFailure{}), nil
}

func (s *transactionalFailureStore) Commit(ctx context.Context) error {
	if s.armed && s.commit {
		s.armed = false

		return oauth2.ErrSerializationFailure
	}

	tx := s.transaction(ctx)
	tx.closed = true

	for _, write := range tx.writes {
		if err := write(context.Background()); err != nil {
			return err
		}

		s.committed++
	}

	return nil
}

func (s *transactionalFailureStore) Rollback(ctx context.Context) error {
	s.transaction(ctx).closed = true

	if s.competing != nil {
		s.competing(context.Background())
		s.competing = nil
	}

	return nil
}

func (s *transactionalFailureStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	if s.armed && !s.commit {
		s.armed = false

		return oauth2.ErrSerializationFailure
	}

	return s.write(ctx, func(ctx context.Context) error {
		return s.serializationStorage.InvalidateAuthorizeCodeSession(ctx, signature)
	})
}

func (s *transactionalFailureStore) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	if s.armed && !s.commit {
		s.armed = false

		return oauth2.ErrSerializationFailure
	}

	return s.write(ctx, func(ctx context.Context) error {
		return s.serializationStorage.RotateRefreshToken(ctx, requestID, signature)
	})
}

func (s *transactionalFailureStore) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	return s.write(ctx, func(ctx context.Context) error {
		return s.serializationStorage.CreateAccessTokenSession(ctx, signature, request)
	})
}

func (s *transactionalFailureStore) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request oauth2.Requester) error {
	return s.write(ctx, func(ctx context.Context) error {
		return s.serializationStorage.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
	})
}

func (s *transactionalFailureStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	if err := s.usable(ctx); err != nil {
		return nil, err
	}

	return s.serializationStorage.GetAuthorizeCodeSession(ctx, signature, session)
}

func (s *transactionalFailureStore) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	if err := s.usable(ctx); err != nil {
		return nil, err
	}

	return s.serializationStorage.GetRefreshTokenSession(ctx, signature, session)
}

func (s *transactionalFailureStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	if err := s.usable(ctx); err != nil {
		return err
	}

	return s.serializationStorage.RevokeAccessToken(ctx, requestID)
}

func (s *transactionalFailureStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	if err := s.usable(ctx); err != nil {
		return err
	}

	return s.serializationStorage.RevokeRefreshToken(ctx, requestID)
}
