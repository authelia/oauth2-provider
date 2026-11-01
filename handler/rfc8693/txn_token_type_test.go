// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestTxnTokenTypesDoNotClaimJWTDispatch(t *testing.T) {
	testCases := []struct {
		name     string
		have     oauth2.RFC8693TokenType
		expected string
	}{
		{"ShouldReturnTxnTokenURN", &TxnTokenType{Name: "txn"}, consts.TokenTypeRFC8693TxnToken},
		{"ShouldReturnSelfSignedURN", &SelfSignedTokenType{Name: "self"}, consts.TokenTypeRFC8693SelfSigned},
		{"ShouldReturnUnsignedJSONURN", &UnsignedJSONTokenType{Name: "json"}, consts.TokenTypeRFC8693UnsignedJSON},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.GetType(t.Context()))
			assert.NotEqual(t, consts.TokenTypeRFC8693JWT, tc.have.GetType(t.Context()))
		})
	}

	assert.Equal(t, "txn", (&TxnTokenType{Name: "txn"}).GetName(t.Context()))
	assert.Equal(t, "self", (&SelfSignedTokenType{Name: "self"}).GetName(t.Context()))
	assert.Equal(t, "json", (&UnsignedJSONTokenType{Name: "json"}).GetName(t.Context()))
}

func TestCustomJWTRefusesTxnTokenType(t *testing.T) {
	for _, typ := range []string{consts.JSONWebTokenTypeTxnToken, "TXNTOKEN+JWT", "application/txntoken+jwt"} {
		t.Run(typ, func(t *testing.T) {
			config := newSpecConfig(t)
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Types = []string{typ, consts.JSONWebTokenTypeTxnToken}

			store := storage.NewExampleStore()
			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			token, _, err := strategy.Encode(t.Context(), jwt.MapClaims{
				consts.ClaimIssuer:         "https://as.example.com",
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{"my-client"},
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
			}, jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: typ}}))
			require.NoError(t, err)

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("peter"), url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {token},
			})

			err = (&CustomJWTTypeHandler{Config: config, Strategy: strategy, Storage: store}).HandleTokenEndpointRequest(t.Context(), request)

			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "cannot be exchanged")
		})
	}
}
