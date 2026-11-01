// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
)

const txnTrustDomain = "trust-domain.example"

type txnRequest struct {
	form               url.Values
	audience, resource []string
	scopes             []string
	omitRequestedType  bool
	omitScope, omitAud bool
	subjectTokenType   string
}

type txnFixture struct {
	config  *oauth2.Config
	client  *oauth2.DefaultClient
	handler *TokenExchangeGrantHandler
}

func newTxnFixture(t *testing.T) *txnFixture {
	t.Helper()

	config := newSpecConfig(t)
	config.RFC8693TokenTypes[consts.TokenTypeRFC8693TxnToken] = &TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, TrustDomain: txnTrustDomain}

	client := &oauth2.DefaultClient{
		ID:           "txn-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
		Scopes:       []string{"photos", "oauth2"},
		Audience:     []string{txnTrustDomain, "https://other.example"},
		Resource:     []string{"https://res.example"},
	}

	return &txnFixture{
		config: config,
		client: client,
		handler: &TokenExchangeGrantHandler{
			Config:           config,
			ScopeStrategy:    oauth2.ExactScopeStrategy,
			AudienceStrategy: oauth2.ExactAudienceStrategy,
			ResourceStrategy: oauth2.ExactAudienceStrategy,
		},
	}
}

func (f *txnFixture) request(r txnRequest) *oauth2.AccessRequest {
	form := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectToken:     {"subject"},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
	}

	if r.subjectTokenType != "" {
		form.Set(consts.FormParameterSubjectTokenType, r.subjectTokenType)
	}

	if !r.omitRequestedType {
		form.Set(consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693TxnToken)
	}

	for name, values := range r.form {
		form[name] = values
	}

	audience, scopes := r.audience, r.scopes

	if audience == nil && !r.omitAud {
		audience = []string{txnTrustDomain}
	}

	if scopes == nil && !r.omitScope {
		scopes = []string{"photos"}
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:                uuid.New().String(),
			Client:            f.client,
			Form:              form,
			RequestedScope:    scopes,
			RequestedAudience: audience,
			RequestedResource: r.resource,
			Session:           newSpecSession(""),
		},
	}
}

func TestTxnTokenRequestRules(t *testing.T) {
	testCases := []struct {
		name     string
		have     txnRequest
		defaults bool
		err      error
		hint     string
	}{
		{"ShouldPassValid", txnRequest{}, false, nil, ""},
		{"ShouldRefuseDefaultedRequestedType", txnRequest{omitRequestedType: true}, true, oauth2.ErrInvalidRequest, "requested_token_type"},
		{"ShouldRefuseMissingAudience", txnRequest{omitAud: true}, false, oauth2.ErrInvalidRequest, "audience"},
		{"ShouldRefuseTwoAudiences", txnRequest{audience: []string{txnTrustDomain, "https://other.example"}}, false, oauth2.ErrInvalidTarget, "audience"},
		{"ShouldRefuseOtherAudience", txnRequest{audience: []string{"https://other.example"}}, false, oauth2.ErrInvalidTarget, "audience"},
		{"ShouldRefuseResource", txnRequest{resource: []string{"https://res.example"}}, false, oauth2.ErrInvalidTarget, "resource"},
		{"ShouldRefuseMissingScope", txnRequest{omitScope: true}, false, oauth2.ErrInvalidRequest, "scope"},
		{"ShouldRefuseTxnTokenSubject", txnRequest{subjectTokenType: consts.TokenTypeRFC8693TxnToken}, false, oauth2.ErrInvalidRequest, "subject_token_type"},
		{"ShouldPassEmptyObjectContext", txnRequest{form: url.Values{consts.FormParameterRequestContext: {"{}"}, consts.FormParameterRequestDetails: {"{}"}}}, false, nil, ""},
	}

	for _, name := range []string{consts.FormParameterRequestContext, consts.FormParameterRequestDetails} {
		for _, value := range []string{"null", "[]", `"x"`, "1", "", "{", `{"a":1} x`} {
			testCases = append(testCases, struct {
				name     string
				have     txnRequest
				defaults bool
				err      error
				hint     string
			}{"ShouldRefuse/" + name + "/" + value, txnRequest{form: url.Values{name: {value}}}, false, oauth2.ErrInvalidRequest, name})
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnFixture(t)

			if tc.defaults {
				f.config.DefaultRequestedTokenType = consts.TokenTypeRFC8693TxnToken
			}

			err := f.handler.HandleTokenEndpointRequest(t.Context(), f.request(tc.have))

			if tc.err == nil {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.err)

			if tc.hint != "" {
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, tc.hint)
			}
		})
	}
}

type txnRefreshStore interface {
	hoauth2.RefreshTokenStorage
	Storage
}

func TestTxnTokenRefusesRefreshTokenSubject(t *testing.T) {
	stores := map[string]txnRefreshStore{
		"ShouldNotRevokeWithExampleStore":   storage.NewExampleStore(),
		"ShouldNotRevokeWithHydratingStore": storage.NewHydratingMemoryStore(),
	}

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			f := newTxnFixture(t)
			core := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: f.config}, Config: f.config}

			issued := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request:    oauth2.Request{ID: uuid.New().String(), Client: f.client, Session: newSpecSession("peter"), GrantedScope: []string{"photos"}},
			}

			token, signature, err := core.GenerateRefreshToken(t.Context(), issued)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued))

			request := f.request(txnRequest{subjectTokenType: consts.TokenTypeRFC8693RefreshToken})
			request.Form.Set(consts.FormParameterSubjectToken, token)

			handlers := []oauth2.TokenEndpointHandler{
				f.handler,
				&RefreshTokenTypeHandler{Config: f.config, RefreshTokenLifespan: 5 * time.Minute, CoreStrategy: core, ScopeStrategy: oauth2.ExactScopeStrategy, Storage: store},
			}

			for _, handler := range handlers {
				if err = handler.HandleTokenEndpointRequest(t.Context(), request); err != nil {
					break
				}
			}

			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectTokenType)

			stored, err := store.GetRefreshTokenSession(t.Context(), signature, newSpecSession(""))
			require.NoError(t, err)
			assert.Equal(t, issued.GetID(), stored.GetID())
		})
	}
}

func TestTxnTokenRefusesAudienceMissingFromClient(t *testing.T) {
	f := newTxnFixture(t)
	f.client.Audience = []string{"https://other.example"}

	err := f.handler.HandleTokenEndpointRequest(t.Context(), f.request(txnRequest{}))

	assert.ErrorIs(t, err, oauth2.ErrInvalidTarget)
	assert.NotContains(t, oauth2.ErrorToRFC6749Error(err).HintField, "Trust Domain")
}

func TestTxnTokenRulesDoNotAffectOtherTypes(t *testing.T) {
	f := newTxnFixture(t)

	request := f.request(txnRequest{
		omitRequestedType: true,
		audience:          []string{txnTrustDomain, "https://other.example"},
		form:              url.Values{consts.FormParameterRequestContext: {"[]"}},
	})

	require.NoError(t, f.handler.HandleTokenEndpointRequest(t.Context(), request))
	assert.Equal(t, oauth2.Arguments{txnTrustDomain, "https://other.example"}, request.GetGrantedAudience())
}
