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

var jwtClaims = &JWTClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().UTC().Round(time.Second),
	Issuer:    "authelia",
	NotBefore: time.Now().UTC().Round(time.Second),
	Audience:  []string{"tests"},
	ExpiresAt: time.Now().UTC().Add(time.Hour).Round(time.Second),
	JTI:       "abcdef",
	Scope:     []string{consts.ScopeEmail, consts.ScopeOffline},
	Extra: map[string]any{
		"foo": "bar",
		"baz": "bar",
	},
	ScopeField: JWTScopeFieldList,
}

var jwtClaimsMap = map[string]any{
	ClaimSubject:          jwtClaims.Subject,
	ClaimIssuedAt:         jwtClaims.IssuedAt.Unix(),
	ClaimIssuer:           jwtClaims.Issuer,
	ClaimNotBefore:        jwtClaims.NotBefore.Unix(),
	ClaimAudience:         jwtClaims.Audience,
	ClaimExpirationTime:   jwtClaims.ExpiresAt.Unix(),
	ClaimJWTID:            jwtClaims.JTI,
	ClaimScopeNonStandard: []string{consts.ScopeEmail, consts.ScopeOffline},
	"foo":                 jwtClaims.Extra["foo"],
	"baz":                 jwtClaims.Extra["baz"],
}

func TestClaimAddGetString(t *testing.T) {
	jwtClaims.Add("foo", "bar")
	assert.Equal(t, "bar", jwtClaims.Get("foo"))
}

func TestClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()[ClaimJWTID])
}

func TestAssert(t *testing.T) {
	assert.Nil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(-2 * time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JWTClaims{NotBefore: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.Nil(t, (&JWTClaims{NotBefore: time.Now().UTC().Add(-time.Hour)}).
		ToMapClaims().Valid())
	assert.Nil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour),
		NotBefore: time.Now().UTC().Add(-time.Hour)}).ToMapClaims().Valid())
}

func TestClaimsToMap(t *testing.T) {
	assert.Equal(t, jwtClaimsMap, jwtClaims.ToMap())
}

func TestClaimsFromMap(t *testing.T) {
	var claims JWTClaims
	claims.FromMap(jwtClaimsMap)
	assert.Equal(t, jwtClaims, &claims)
}

func TestScopeFieldString(t *testing.T) {
	jwtClaimsWithString := jwtClaims.WithScopeField(JWTScopeFieldString)
	// Making a copy of jwtClaimsMap.
	jwtClaimsMapWithString := jwtClaims.ToMap()
	delete(jwtClaimsMapWithString, ClaimScopeNonStandard)
	jwtClaimsMapWithString[ClaimScope] = "email offline"
	assert.Equal(t, jwtClaimsMapWithString, map[string]any(jwtClaimsWithString.ToMapClaims()))
	var claims JWTClaims
	claims.FromMap(jwtClaimsMapWithString)
	assert.Equal(t, jwtClaimsWithString, &claims)
}

func TestScopeFieldBoth(t *testing.T) {
	jwtClaimsWithBoth := jwtClaims.WithScopeField(JWTScopeFieldBoth)
	// Making a copy of jwtClaimsMap
	jwtClaimsMapWithBoth := jwtClaims.ToMap()
	jwtClaimsMapWithBoth[ClaimScope] = "email offline"
	assert.Equal(t, jwtClaimsMapWithBoth, map[string]any(jwtClaimsWithBoth.ToMapClaims()))
	var claims JWTClaims
	claims.FromMap(jwtClaimsMapWithBoth)
	assert.Equal(t, jwtClaimsWithBoth, &claims)
}
