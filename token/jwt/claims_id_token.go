// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/consts"
)

// IDTokenClaims represent the claims used in open id connect requests
type IDTokenClaims struct {
	JTI                                 string         `json:"jti"`
	Issuer                              string         `json:"iss"`
	Subject                             string         `json:"sub"`
	Audience                            []string       `json:"aud"`
	Nonce                               string         `json:"nonce"`
	ExpiresAt                           time.Time      `json:"exp"`
	IssuedAt                            time.Time      `json:"iat"`
	RequestedAt                         time.Time      `json:"rat"`
	AuthTime                            time.Time      `json:"auth_time"`
	AccessTokenHash                     string         `json:"at_hash"`
	AuthenticationContextClassReference string         `json:"acr"`
	AuthenticationMethodsReferences     []string       `json:"amr"`
	CodeHash                            string         `json:"c_hash"`
	Extra                               map[string]any `json:"ext"`
}

// ToMap will transform the headers to a map structure
func (c *IDTokenClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

	if c.Subject != "" {
		ret[consts.ClaimSubject] = c.Subject
	} else {
		delete(ret, consts.ClaimSubject)
	}

	if c.Issuer != "" {
		ret[consts.ClaimIssuer] = c.Issuer
	} else {
		delete(ret, consts.ClaimIssuer)
	}

	if c.JTI != "" {
		ret[consts.ClaimJWTID] = c.JTI
	} else {
		ret[consts.ClaimJWTID] = uuid.New().String()
	}

	if len(c.Audience) > 0 {
		ret[consts.ClaimAudience] = c.Audience
	} else {
		ret[consts.ClaimAudience] = []string{}
	}

	if !c.IssuedAt.IsZero() {
		ret[consts.ClaimIssuedAt] = c.IssuedAt.Unix()
	} else {
		delete(ret, consts.ClaimIssuedAt)
	}

	if !c.ExpiresAt.IsZero() {
		ret[consts.ClaimExpirationTime] = c.ExpiresAt.Unix()
	} else {
		delete(ret, consts.ClaimExpirationTime)
	}

	if !c.RequestedAt.IsZero() {
		ret[consts.ClaimRequestedAt] = c.RequestedAt.Unix()
	} else {
		delete(ret, consts.ClaimRequestedAt)
	}

	if len(c.Nonce) > 0 {
		ret[consts.ClaimNonce] = c.Nonce
	} else {
		delete(ret, consts.ClaimNonce)
	}

	if len(c.AccessTokenHash) > 0 {
		ret[consts.ClaimAccessTokenHash] = c.AccessTokenHash
	} else {
		delete(ret, consts.ClaimAccessTokenHash)
	}

	if len(c.CodeHash) > 0 {
		ret[consts.ClaimCodeHash] = c.CodeHash
	} else {
		delete(ret, consts.ClaimCodeHash)
	}

	if !c.AuthTime.IsZero() {
		ret[consts.ClaimAuthenticationTime] = c.AuthTime.Unix()
	} else {
		delete(ret, consts.ClaimAuthenticationTime)
	}

	if len(c.AuthenticationContextClassReference) > 0 {
		ret[consts.ClaimAuthenticationContextClassReference] = c.AuthenticationContextClassReference
	} else {
		delete(ret, consts.ClaimAuthenticationContextClassReference)
	}

	if len(c.AuthenticationMethodsReferences) > 0 {
		ret[consts.ClaimAuthenticationMethodsReference] = c.AuthenticationMethodsReferences
	} else {
		delete(ret, consts.ClaimAuthenticationMethodsReference)
	}

	return ret
}

// Add will add a key-value pair to the extra field
func (c *IDTokenClaims) Add(key string, value any) {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c *IDTokenClaims) Get(key string) any {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c IDTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}
