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

func TestIDTokenClaims_Valid(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *IDTokenClaims
		wantErr bool
	}{
		{
			name:    "ShouldPassFutureExpiration",
			claims:  &IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))},
			wantErr: false,
		},
		{
			name:    "ShouldFailPastExpiration",
			claims:  &IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.claims.ToMapClaims().Valid()

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIDTokenClaims_ToMapClaimsSetsID(t *testing.T) {
	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()[ClaimJWTID])
}

func TestIDTokenClaims_ToMap(t *testing.T) {
	base := &IDTokenClaims{
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

	testCases := []struct {
		name     string
		mutate   func(c *IDTokenClaims)
		expected func(c *IDTokenClaims) map[string]any
	}{
		{
			name:   "ShouldOmitNonceWhenEmpty",
			mutate: func(c *IDTokenClaims) {},
			expected: func(c *IDTokenClaims) map[string]any {
				return map[string]any{
					ClaimJWTID:              c.JTI,
					ClaimSubject:            c.Subject,
					ClaimIssuedAt:           c.IssuedAt.Unix(),
					ClaimIssuer:             c.Issuer,
					ClaimAudience:           c.Audience,
					ClaimExpirationTime:     c.ExpirationTime.Unix(),
					"foo":                   c.Extra["foo"],
					"baz":                   c.Extra["baz"],
					ClaimAccessTokenHash:    c.AccessTokenHash,
					ClaimCodeHash:           c.CodeHash,
					ClaimStateHash:          c.StateHash,
					ClaimAuthenticationTime: c.AuthTime.Unix(),
					consts.ClaimAuthenticationContextClassReference: c.AuthenticationContextClassReference,
					consts.ClaimAuthenticationMethodsReference:      c.AuthenticationMethodsReferences,
				}
			},
		},
		{
			name: "ShouldIncludeNonceWhenSet",
			mutate: func(c *IDTokenClaims) {
				c.Nonce = "foobar"
			},
			expected: func(c *IDTokenClaims) map[string]any {
				return map[string]any{
					consts.ClaimJWTID:              c.JTI,
					consts.ClaimSubject:            c.Subject,
					consts.ClaimIssuedAt:           c.IssuedAt.Unix(),
					consts.ClaimIssuer:             c.Issuer,
					consts.ClaimAudience:           c.Audience,
					consts.ClaimExpirationTime:     c.ExpirationTime.Unix(),
					"foo":                          c.Extra["foo"],
					"baz":                          c.Extra["baz"],
					consts.ClaimAccessTokenHash:    c.AccessTokenHash,
					consts.ClaimCodeHash:           c.CodeHash,
					consts.ClaimStateHash:          c.StateHash,
					consts.ClaimAuthenticationTime: c.AuthTime.Unix(),
					consts.ClaimAuthenticationContextClassReference: c.AuthenticationContextClassReference,
					consts.ClaimAuthenticationMethodsReference:      c.AuthenticationMethodsReferences,
					consts.ClaimNonce: c.Nonce,
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := *base
			tc.mutate(&c)
			assert.Equal(t, tc.expected(&c), c.ToMap())
		})
	}
}

func TestIDTokenClaims_FromMap(t *testing.T) {
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

	testCases := []struct {
		name string
		fn   func(c *IDTokenClaims)
	}{
		{
			name: "ShouldDecodeFromMap",
			fn: func(c *IDTokenClaims) {
				c.FromMap(m)
			},
		},
		{
			name: "ShouldDecodeFromMapClaims",
			fn: func(c *IDTokenClaims) {
				c.FromMapClaims(MapClaims(m))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual IDTokenClaims
			tc.fn(&actual)
			assert.Equal(t, expected, &actual)
		})
	}
}

func TestIDTokenClaims_RoundTrip(t *testing.T) {
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

func TestIDTokenClaims_FromMapExtra(t *testing.T) {
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
