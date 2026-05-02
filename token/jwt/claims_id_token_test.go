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

func TestIDTokenClaimsFromMap(t *testing.T) {
	expected := &IDTokenClaims{
		JTI:                                 "foo-id",
		Issuer:                              "authelia",
		Subject:                             "peter",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:                            Now(),
		AuthTime:                            Now(),
		Nonce:                               "nonce-value",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		AuthorizedParty:                     "client-id",
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	m := map[string]any{
		ClaimJWTID:                               expected.JTI,
		ClaimIssuer:                              expected.Issuer,
		ClaimSubject:                             expected.Subject,
		ClaimAudience:                            expected.Audience,
		ClaimExpirationTime:                      expected.ExpirationTime.Unix(),
		ClaimIssuedAt:                            expected.IssuedAt.Unix(),
		ClaimAuthenticationTime:                  expected.AuthTime.Unix(),
		ClaimNonce:                               expected.Nonce,
		ClaimAuthenticationContextClassReference: expected.AuthenticationContextClassReference,
		ClaimAuthenticationMethodsReference:      expected.AuthenticationMethodsReferences,
		ClaimAuthorizedParty:                     expected.AuthorizedParty,
		ClaimAccessTokenHash:                     expected.AccessTokenHash,
		ClaimCodeHash:                            expected.CodeHash,
		ClaimStateHash:                           expected.StateHash,
		"foo":                                    "bar",
		"baz":                                    "bar",
	}

	var actual IDTokenClaims

	actual.FromMap(m)
	assert.Equal(t, expected, &actual)

	var actualFromMapClaims IDTokenClaims

	actualFromMapClaims.FromMapClaims(MapClaims(m))
	assert.Equal(t, expected, &actualFromMapClaims)
}

func TestIDTokenClaimsRoundTrip(t *testing.T) {
	original := &IDTokenClaims{
		JTI:                                 "foo-id",
		Issuer:                              "authelia",
		Subject:                             "peter",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:                            Now(),
		AuthTime:                            Now(),
		Nonce:                               "nonce-value",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		AuthorizedParty:                     "client-id",
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	var roundTripped IDTokenClaims

	roundTripped.FromMap(original.ToMap())
	assert.Equal(t, original, &roundTripped)

	originalMap := original.ToMap()
	assert.Equal(t, originalMap, roundTripped.ToMap())
}

func TestIDTokenClaimsFromMapExtra(t *testing.T) {
	m := map[string]any{
		ClaimJWTID:   "foo-id",
		ClaimSubject: "peter",
		ClaimExtra: map[string]any{
			"foo": "bar",
		},
	}

	var actual IDTokenClaims

	actual.FromMap(m)
	assert.Equal(t, "foo-id", actual.JTI)
	assert.Equal(t, "peter", actual.Subject)
	assert.Equal(t, map[string]any{"foo": "bar"}, actual.Extra)
}
