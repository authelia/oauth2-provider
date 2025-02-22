// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2/token/jwt"
)

var jarmClaims = &JARMClaims{
	Issuer:         "authelia",
	Audience:       []string{"tests"},
	JTI:            "abcdef",
	IssuedAt:       Now(),
	ExpirationTime: NewNumericDate(time.Now().Add(time.Hour)),
	Extra: map[string]any{
		"foo": "bar",
		"baz": "bar",
	},
}

var jarmClaimsMap = map[string]any{
	ClaimIssuer:         jwtClaims.Issuer,
	ClaimAudience:       jwtClaims.Audience,
	ClaimJWTID:          jwtClaims.JTI,
	ClaimIssuedAt:       jwtClaims.IssuedAt.Unix(),
	ClaimExpirationTime: jwtClaims.ExpiresAt.Unix(),
	"foo":               jwtClaims.Extra["foo"],
	"baz":               jwtClaims.Extra["baz"],
}

func TestJARMClaimAddGetString(t *testing.T) {
	jarmClaims.Add("foo", "bar")
	assert.Equal(t, "bar", jarmClaims.Get("foo"))
}

func TestJARMClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JARMClaims{}).ToMap()[ClaimJWTID])
}

func TestJARMAssert(t *testing.T) {
	assert.Nil(t, (&JARMClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JARMClaims{ExpirationTime: NewNumericDate(time.Now().Add(-2 * time.Hour))}).
		ToMapClaims().Valid())
}

func TestJARMtClaimsToMap(t *testing.T) {
	assert.Equal(t, jarmClaimsMap, jarmClaims.ToMap())
}

func TestJARMClaimsFromMap(t *testing.T) {
	var claims JARMClaims

	claims.FromMap(jarmClaimsMap)
	assert.Equal(t, jarmClaims, &claims)
}
