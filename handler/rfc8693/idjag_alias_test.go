// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestIDJAGRequestRefreshTokenSubjectAudienceAlias(t *testing.T) {
	const alias = "urn:example:alias"

	testCases := []struct {
		name      string
		issuer    string
		owner     string
		requested string
		err       error
	}{
		// Section 4.3: an alias resolves to the issuer identifier, so the comparison applies (Section 4.3.3).
		{name: "ShouldRejectAScopeNotGrantedForAnAliasOfThisServer", issuer: idjagAudience, owner: idjagClientID, requested: idjagOtherScope, err: oauth2.ErrInvalidScope},
		{name: "ShouldAcceptAGrantedScopeForAnAliasOfThisServer", issuer: idjagAudience, owner: idjagClientID, requested: idjagScope},
		{name: "ShouldAcceptAScopeNotGrantedForAnAliasOfAnotherServer", issuer: idjagOtherAudience, owner: idjagClientID, requested: idjagOtherScope},
		{name: "ShouldAcceptAScopeNotGrantedForAnUnknownAudience", requested: idjagOtherScope},
		{name: "ShouldDenyAnAliasOfAnotherClient", issuer: idjagAudience, owner: "another-client", requested: idjagScope, err: oauth2.ErrAccessDenied},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}
			cfg.AuthorizationServerIdentificationIssuer = idjagAudience

			if tc.issuer != "" {
				store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: tc.owner, Audience: alias}] = oauth2.IDJAGRelationship{Issuer: tc.issuer, ClientID: "rs-client"}
			}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)
			client := newIDJAGRegisteredClient()

			refreshToken := createIDJAGRefreshToken(t, strategy, store, client, []string{idjagScope}, []string{idjagAudience}, nil)

			request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {refreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
			})
			request.RequestedScope = oauth2.Arguments{tc.requested}
			request.RequestedAudience = oauth2.Arguments{alias}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestIDJAGRequestRefreshTokenSubjectAudienceAliasStorageError(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}
	cfg.AuthorizationServerIdentificationIssuer = idjagAudience

	handler := newRefreshTokenTypeHandler(cfg, store, strategy)
	handler.Storage = &failingRelationshipStore{MemoryStore: store}

	client := newIDJAGRegisteredClient()

	request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
		consts.FormParameterSubjectToken:       {createIDJAGRefreshToken(t, strategy, store, client, []string{idjagScope}, []string{idjagAudience}, nil)},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
	})
	request.RequestedScope = oauth2.Arguments{idjagScope}
	request.RequestedAudience = oauth2.Arguments{"urn:example:alias"}

	require.ErrorIs(t, handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrServerError)
}

type failingRelationshipStore struct {
	*storage.MemoryStore
}

func (s *failingRelationshipStore) GetIDJAGRelationship(_ context.Context, _ oauth2.AccessRequester, _ string) (*oauth2.IDJAGRelationship, error) {
	return nil, errors.New("unavailable")
}
