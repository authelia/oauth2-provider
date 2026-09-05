// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
)

func TestExchangeRejectsUnclaimedSubjectTokenType(t *testing.T) {
	const unclaimed = "urn:ietf:params:oauth:token-type:saml2"

	store := storage.NewExampleStore()

	config := &oauth2.Config{
		ScopeStrategy:    oauth2.HierarchicScopeStrategy,
		AudienceStrategy: oauth2.DefaultAudienceStrategy,
		GlobalSecret:     []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			unclaimed:                          &DefaultTokenType{Name: unclaimed},
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}

	coreStrategy := &hoauth2.HMACCoreStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}

	handlers := []oauth2.TokenEndpointHandler{
		&TokenExchangeGrantHandler{
			Config:           config,
			ScopeStrategy:    config.ScopeStrategy,
			AudienceStrategy: config.AudienceStrategy,
			ResourceStrategy: config.GetResourceStrategy(t.Context()),
		},
		&AccessTokenTypeHandler{
			Config:               config,
			AccessTokenLifespan:  5 * time.Minute,
			RefreshTokenLifespan: 5 * time.Minute,
			RefreshTokenScopes:   []string{"offline"},
			CoreStrategy:         coreStrategy,
			ScopeStrategy:        config.ScopeStrategy,
			Storage:              store,
		},
		&ActorTokenValidationHandler{},
	}

	areq := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: []string{unclaimed},
				consts.FormParameterSubjectToken:     []string{"not-a-token-at-all"},
			},
			Session: &DefaultSession{
				DefaultSession: &openid.DefaultSession{},
				Extra:          map[string]any{},
			},
		},
	}

	ctx := t.Context()
	aresp := oauth2.NewAccessResponse()

	var err error

	for _, handler := range handlers {
		if !handler.CanHandleTokenEndpointRequest(ctx, areq) {
			continue
		}

		if err = handler.HandleTokenEndpointRequest(ctx, areq); errors.Is(err, oauth2.ErrUnknownRequest) {
			err = nil

			continue
		} else if err != nil {
			break
		}
	}

	if err == nil {
		for _, handler := range handlers {
			if !handler.CanHandleTokenEndpointRequest(ctx, areq) {
				continue
			}

			if err = handler.PopulateTokenEndpointResponse(ctx, areq, aresp); errors.Is(err, oauth2.ErrUnknownRequest) {
				err = nil

				continue
			} else if err != nil {
				break
			}
		}
	}

	require.Error(t, err)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'urn:ietf:params:oauth:token-type:saml2' token type is not supported as a 'subject_token_type'. The 'subject_token_type' value 'urn:ietf:params:oauth:token-type:saml2' is registered in the token types configuration but no token type handler validated a subject token for it, so the 'subject_token' was never read. A registered type must be claimed by one of the token type handlers, being one of the three built-in types or a '*rfc8693.JWTType'.")
	assert.Empty(t, aresp.AccessToken)
}
