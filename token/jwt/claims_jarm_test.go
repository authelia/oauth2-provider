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

var jarmClaims = &JARMClaims{
	Issuer:    "authelia",
	Audience:  []string{"tests"},
	JTI:       "abcdef",
	IssuedAt:  time.Now().UTC().Round(time.Second),
	ExpiresAt: time.Now().UTC().Add(time.Hour).Round(time.Second),
	Extra: map[string]any{
		"foo": "bar",
		"baz": "bar",
	},
}

var jarmClaimsMap = map[string]any{
	consts.ClaimIssuer:         jwtClaims.Issuer,
	consts.ClaimAudience:       jwtClaims.Audience,
	consts.ClaimJWTID:          jwtClaims.JTI,
	consts.ClaimIssuedAt:       jwtClaims.IssuedAt.Unix(),
	consts.ClaimExpirationTime: jwtClaims.ExpiresAt.Unix(),
	"foo":                      jwtClaims.Extra["foo"],
	"baz":                      jwtClaims.Extra["baz"],
}

func TestJARMClaimAddGetString(t *testing.T) {
	jarmClaims.Add("foo", "bar")
	assert.Equal(t, "bar", jarmClaims.Get("foo"))
}

func TestJARMClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JARMClaims{}).ToMap()[consts.ClaimJWTID])
}

func TestJARMAssert(t *testing.T) {
	assert.Nil(t, (&JARMClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JARMClaims{ExpiresAt: time.Now().UTC().Add(-2 * time.Hour)}).
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
