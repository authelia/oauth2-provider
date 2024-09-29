// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
	. "authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenAssert(t *testing.T) {
	assert.NoError(t, (&IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))}).
		ToMapClaims().Valid())
	assert.Error(t, (&IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))}).
		ToMapClaims().Valid())

	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()[ClaimJWTID])
}

func TestIDTokenClaimsToMap(t *testing.T) {
	idTokenClaims := &IDTokenClaims{
		JTI:                                 "foo-id",
		Subject:                             "peter",
		IssuedAt:                            Now(),
		Issuer:                              "authelia",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		AuthTime:                            Now(),
		RequestedAt:                         Now(),
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}
	assert.Equal(t, map[string]any{
		ClaimJWTID:              idTokenClaims.JTI,
		ClaimSubject:            idTokenClaims.Subject,
		ClaimIssuedAt:           idTokenClaims.IssuedAt.Unix(),
		ClaimIssuer:             idTokenClaims.Issuer,
		ClaimAudience:           idTokenClaims.Audience,
		ClaimExpirationTime:     idTokenClaims.ExpirationTime.Unix(),
		"foo":                   idTokenClaims.Extra["foo"],
		"baz":                   idTokenClaims.Extra["baz"],
		ClaimAccessTokenHash:    idTokenClaims.AccessTokenHash,
		ClaimCodeHash:           idTokenClaims.CodeHash,
		ClaimStateHash:          idTokenClaims.StateHash,
		ClaimAuthenticationTime: idTokenClaims.AuthTime.Unix(),
		consts.ClaimAuthenticationContextClassReference: idTokenClaims.AuthenticationContextClassReference,
		consts.ClaimAuthenticationMethodsReference:      idTokenClaims.AuthenticationMethodsReferences,
	}, idTokenClaims.ToMap())

	idTokenClaims.Nonce = "foobar"
	assert.Equal(t, map[string]any{
		consts.ClaimJWTID:              idTokenClaims.JTI,
		consts.ClaimSubject:            idTokenClaims.Subject,
		consts.ClaimIssuedAt:           idTokenClaims.IssuedAt.Unix(),
		consts.ClaimIssuer:             idTokenClaims.Issuer,
		consts.ClaimAudience:           idTokenClaims.Audience,
		consts.ClaimExpirationTime:     idTokenClaims.ExpirationTime.Unix(),
		"foo":                          idTokenClaims.Extra["foo"],
		"baz":                          idTokenClaims.Extra["baz"],
		consts.ClaimAccessTokenHash:    idTokenClaims.AccessTokenHash,
		consts.ClaimCodeHash:           idTokenClaims.CodeHash,
		consts.ClaimStateHash:          idTokenClaims.StateHash,
		consts.ClaimAuthenticationTime: idTokenClaims.AuthTime.Unix(),
		consts.ClaimAuthenticationContextClassReference: idTokenClaims.AuthenticationContextClassReference,
		consts.ClaimAuthenticationMethodsReference:      idTokenClaims.AuthenticationMethodsReferences,
		consts.ClaimNonce: idTokenClaims.Nonce,
	}, idTokenClaims.ToMap())
}
