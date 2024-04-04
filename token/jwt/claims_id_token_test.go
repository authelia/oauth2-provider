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
	assert.NoError(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.Error(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(-time.Hour)}).
		ToMapClaims().Valid())

	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()[consts.ClaimJWTID])
}

func TestIDTokenClaimsToMap(t *testing.T) {
	idTokenClaims := &IDTokenClaims{
		JTI:                                 "foo-id",
		Subject:                             "peter",
		IssuedAt:                            time.Now().UTC().Round(time.Second),
		Issuer:                              "authelia",
		Audience:                            []string{"tests"},
		ExpiresAt:                           time.Now().UTC().Add(time.Hour).Round(time.Second),
		AuthTime:                            time.Now().UTC(),
		RequestedAt:                         time.Now().UTC(),
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
		consts.ClaimJWTID:              idTokenClaims.JTI,
		consts.ClaimSubject:            idTokenClaims.Subject,
		consts.ClaimIssuedAt:           idTokenClaims.IssuedAt.Unix(),
		consts.ClaimIssuer:             idTokenClaims.Issuer,
		consts.ClaimAudience:           idTokenClaims.Audience,
		consts.ClaimExpirationTime:     idTokenClaims.ExpiresAt.Unix(),
		"foo":                          idTokenClaims.Extra["foo"],
		"baz":                          idTokenClaims.Extra["baz"],
		consts.ClaimAccessTokenHash:    idTokenClaims.AccessTokenHash,
		consts.ClaimCodeHash:           idTokenClaims.CodeHash,
		consts.ClaimStateHash:          idTokenClaims.StateHash,
		consts.ClaimAuthenticationTime: idTokenClaims.AuthTime.Unix(),
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
		consts.ClaimExpirationTime:     idTokenClaims.ExpiresAt.Unix(),
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
