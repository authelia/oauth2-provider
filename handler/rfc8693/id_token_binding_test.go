// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenSubjectTokenInheritsItsConfirmation(t *testing.T) {
	confirmationKey, confirmationJKT := newConfirmationKey(t)
	otherKey, otherJKT := newConfirmationKey(t)

	testCases := []struct {
		name     string
		cnf      any
		expected string
		jkt      string
		x5t      string
	}{
		{
			name: "ShouldInheritTheKeyBindingJWK",
			cnf:  map[string]any{consts.ClaimConfirmationJWK: confirmationKey},
			jkt:  confirmationJKT,
		},
		{
			name: "ShouldInheritADPoPThumbprint",
			cnf:  map[string]any{jwt.ClaimConfirmationJWKThumbprint: confirmationJKT},
			jkt:  confirmationJKT,
		},
		{
			name: "ShouldInheritACertificateThumbprint",
			cnf:  map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: bindingX5T},
			x5t:  bindingX5T,
		},
		{
			name: "ShouldInheritBothAJWKAndACertificateThumbprint",
			cnf: map[string]any{
				consts.ClaimConfirmationJWK:               confirmationKey,
				jwt.ClaimConfirmationX509SHA256Thumbprint: bindingX5T,
			},
			jkt: confirmationJKT,
			x5t: bindingX5T,
		},
		{
			name: "ShouldRecordNothingWithoutAConfirmation",
			cnf:  nil,
		},
		{
			name: "ShouldRecordNothingForAConfirmationThatIsNotAnObject",
			cnf:  "not-an-object",
		},
		{
			name:     "ShouldRejectAnUnreadableKey",
			cnf:      map[string]any{consts.ClaimConfirmationJWK: map[string]any{"kty": "EC", "crv": "P-256", "x": "!!!"}},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'cnf' claim of the presented token carries a 'jwk' that could not be read as a JSON Web Key. illegal base64 data at input byte 0",
		},
		{
			name: "ShouldRejectAJWKAndThumbprintNamingDifferentKeys",
			cnf: map[string]any{
				consts.ClaimConfirmationJWK:        confirmationKey,
				jwt.ClaimConfirmationJWKThumbprint: otherJKT,
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'cnf' claim of the presented token carries a 'jkt' and a 'jwk' that identify different keys.",
		},
		{
			name: "ShouldAcceptAJWKAndThumbprintNamingTheSameKey",
			cnf: map[string]any{
				consts.ClaimConfirmationJWK:        confirmationKey,
				jwt.ClaimConfirmationJWKThumbprint: confirmationJKT,
			},
			jkt: confirmationJKT,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := runIDTokenBindingExchange(t, tc.cnf, nil)

			if tc.expected != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.jkt, session.GetDPoPJWKThumbprint())
			assert.Equal(t, tc.x5t, session.GetClientCertificateSHA256Thumbprint())
		})
	}

	t.Run("ShouldRejectASubjectAndActorBoundToDifferentKeys", func(t *testing.T) {
		_, err := runIDTokenBindingExchange(t,
			map[string]any{consts.ClaimConfirmationJWK: confirmationKey},
			map[string]any{consts.ClaimConfirmationJWK: otherKey},
		)

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The subject token and the actor token are bound to different keys or certificates, and the issued token can only carry one binding.")
	})

	t.Run("ShouldRejectTheExchangeWhenNoDPoPProofIsPresented", func(t *testing.T) {
		session, err := runIDTokenBindingExchange(t, map[string]any{consts.ClaimConfirmationJWK: confirmationKey}, nil)

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		require.Equal(t, confirmationJKT, session.GetDPoPJWKThumbprint(), "the binding must be recorded before the binding phase runs")

		binder := &rfc9449.Handler{Config: &oauth2.Config{DPoPEnabled: true}}

		request := &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
			Request:    oauth2.Request{Session: session},
		}

		ctx := context.WithValue(t.Context(), oauth2.RequestContextKey, httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil))

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(binder.BindAccessRequest(ctx, request)), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
	})
}

func runIDTokenBindingExchange(t *testing.T, subject, actor any) (session *DefaultSession, err error) {
	t.Helper()

	store := storage.NewExampleStore()
	config := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	handler := &IDTokenTypeHandler{
		Config:             config,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: config},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	idToken := func(cnf any) string {
		claims := jwt.MapClaims{
			consts.ClaimSubject:        "peter",
			consts.ClaimAudience:       []string{client.GetID()},
			consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
			consts.ClaimIssuedAt:       time.Now().Unix(),
		}

		if cnf != nil {
			claims[jwt.ClaimConfirmation] = cnf
		}

		return createJWT(t.Context(), client, jwtStrategy, claims)
	}

	form := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
		consts.FormParameterSubjectToken:     {idToken(subject)},
	}

	if actor != nil {
		form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693IDToken)
		form.Set(consts.FormParameterActorToken, idToken(actor))
	}

	session = newSpecSession("peter")

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Form:    form,
			Session: session,
		},
	}

	return session, handler.HandleTokenEndpointRequest(t.Context(), request)
}

func newConfirmationKey(t *testing.T) (jwk map[string]any, jkt string) {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key := &jose.JSONWebKey{Key: &private.PublicKey}

	jkt, err = jwt.ThumbprintJWK(key)
	require.NoError(t, err)

	raw, err := key.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(raw, &jwk))

	return jwk, jkt
}
