// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	jjson "github.com/go-jose/go-jose/v4/json"
	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// IDTokenClaims represent the claims used in open id connect requests
type IDTokenClaims struct {
	JTI                                 string         `json:"jti"`
	Issuer                              string         `json:"iss"`
	Subject                             string         `json:"sub"`
	Audience                            []string       `json:"aud"`
	ExpirationTime                      *NumericDate   `json:"exp"`
	IssuedAt                            *NumericDate   `json:"iat"`
	AuthTime                            *NumericDate   `json:"auth_time,omitempty"`
	Nonce                               string         `json:"nonce,omitempty"`
	AuthenticationContextClassReference string         `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string       `json:"amr,omitempty"`
	AuthorizedParty                     string         `json:"azp,omitempty"`
	AccessTokenHash                     string         `json:"at_hash,omitempty"`
	CodeHash                            string         `json:"c_hash,omitempty"`
	StateHash                           string         `json:"s_hash,omitempty"`
	Extra                               map[string]any `json:"ext,omitempty"`
}

func (c *IDTokenClaims) GetExpirationTime() (exp *NumericDate, err error) {
	return c.ExpirationTime, nil
}

func (c *IDTokenClaims) GetIssuedAt() (iat *NumericDate, err error) {
	return c.IssuedAt, nil
}

func (c *IDTokenClaims) GetNotBefore() (nbf *NumericDate, err error) {
	return toNumericDate(ClaimNotBefore)
}

func (c *IDTokenClaims) GetIssuer() (iss string, err error) {
	return c.Issuer, nil
}

func (c *IDTokenClaims) GetSubject() (sub string, err error) {
	return c.Subject, nil
}

func (c *IDTokenClaims) GetAudience() (aud ClaimStrings, err error) {
	return c.Audience, nil
}

func (c IDTokenClaims) Valid(opts ...ClaimValidationOption) (err error) {
	vopts := &ClaimValidationOptions{}

	for _, opt := range opts {
		opt(vopts)
	}

	var now int64

	if vopts.timef != nil {
		now = vopts.timef().UTC().Unix()
	} else {
		now = TimeFunc().UTC().Unix()
	}

	vErr := new(ValidationError)

	var date *NumericDate

	if date, err = c.GetExpirationTime(); !validDate(validInt64Future, now, vopts.expRequired, date, err) {
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if date, err = c.GetIssuedAt(); !validDate(validInt64Past, now, vopts.expRequired, date, err) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if date, err = c.GetNotBefore(); !validDate(validInt64Past, now, vopts.expRequired, date, err) {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	var str string

	if len(vopts.iss) != 0 {
		if str, err = c.GetIssuer(); err != nil {
			vErr.Inner = errors.New("Token has invalid issuer")
			vErr.Errors |= ValidationErrorIssuer
		} else if !validString(str, vopts.iss, !vopts.issNotRequired) {
			vErr.Inner = errors.New("Token has invalid issuer")
			vErr.Errors |= ValidationErrorIssuer
		}
	}

	if len(vopts.sub) != 0 {
		if str, err = c.GetSubject(); err != nil {
			vErr.Inner = errors.New("Token has invalid subject")
			vErr.Errors |= ValidationErrorIssuer
		} else if !validString(str, vopts.sub, true) {
			vErr.Inner = errors.New("Token has invalid subject")
			vErr.Errors |= ValidationErrorSubject
		}
	}

	var aud ClaimStrings

	if len(vopts.aud) != 0 {
		if aud, err = c.GetAudience(); err != nil || aud == nil || !aud.ValidAny(vopts.aud, !vopts.audNotRequired) {
			vErr.Inner = errors.New("Token has invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if len(vopts.audAll) != 0 {
		if aud, err = c.GetAudience(); err != nil || aud == nil || !aud.ValidAll(vopts.audAll, !vopts.audNotRequired) {
			vErr.Inner = errors.New("Token has invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

func (c *IDTokenClaims) GetExpirationTimeSafe() time.Time {
	if c.ExpirationTime == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.ExpirationTime.UTC()
}

func (c *IDTokenClaims) GetIssuedAtSafe() time.Time {
	if c.IssuedAt == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.IssuedAt.UTC()
}

func (c *IDTokenClaims) GetAuthTimeSafe() time.Time {
	if c.AuthTime == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.AuthTime.UTC()
}

func (c *IDTokenClaims) UnmarshalJSON(data []byte) error {
	claims := MapClaims{}

	decoder := jjson.NewDecoder(bytes.NewReader(data))
	decoder.SetNumberType(jjson.UnmarshalIntOrFloat)

	if err := decoder.Decode(&claims); err != nil {
		return errorsx.WithStack(err)
	}

	var (
		ok  bool
		err error
	)

	for claim, value := range claims {
		ok = false

		switch claim {
		case ClaimJWTID:
			c.JTI, ok = value.(string)
		case ClaimIssuer:
			c.Issuer, ok = value.(string)
		case ClaimSubject:
			c.Subject, ok = value.(string)
		case ClaimAudience:
			c.Audience, ok = toStringSlice(value)
		case ClaimExpirationTime:
			if c.ExpirationTime, err = toNumericDate(value); err == nil {
				ok = true
			}
		case ClaimIssuedAt:
			if c.IssuedAt, err = toNumericDate(value); err == nil {
				ok = true
			}
		case ClaimAuthenticationTime:
			if c.AuthTime, err = toNumericDate(value); err == nil {
				ok = true
			}
		case ClaimNonce:
			c.Nonce, ok = value.(string)
		case ClaimAuthenticationContextClassReference:
			c.AuthenticationContextClassReference, ok = value.(string)
		case ClaimAuthenticationMethodsReference:
			c.AuthenticationMethodsReferences, ok = toStringSlice(value)
		case ClaimAuthorizedParty:
			c.AuthorizedParty, ok = value.(string)
		case ClaimAccessTokenHash:
			c.AccessTokenHash, ok = value.(string)
		case ClaimCodeHash:
			c.CodeHash, ok = value.(string)
		case ClaimStateHash:
			c.StateHash, ok = value.(string)
		case ClaimExtra:
			c.Extra, ok = value.(map[string]any)
		default:
			if c.Extra == nil {
				c.Extra = make(map[string]any)
			}

			c.Extra[claim] = value

			continue
		}

		if !ok {
			return fmt.Errorf("claim %s with value %v could not be decoded", claim, value)
		}
	}

	return nil
}

// ToMap will transform the headers to a map structure
func (c *IDTokenClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

	if c.JTI != "" {
		ret[ClaimJWTID] = c.JTI
	} else {
		ret[ClaimJWTID] = uuid.New().String()
	}

	if c.Issuer != "" {
		ret[ClaimIssuer] = c.Issuer
	} else {
		delete(ret, consts.ClaimIssuer)
	}

	if c.Subject != "" {
		ret[ClaimSubject] = c.Subject
	} else {
		delete(ret, ClaimSubject)
	}

	if len(c.Audience) > 0 {
		ret[ClaimAudience] = c.Audience
	} else {
		delete(ret, ClaimAudience)
	}

	if c.ExpirationTime != nil {
		ret[ClaimExpirationTime] = c.ExpirationTime.Unix()
	} else {
		delete(ret, ClaimExpirationTime)
	}

	if c.IssuedAt != nil {
		ret[ClaimIssuedAt] = c.IssuedAt.Unix()
	} else {
		delete(ret, ClaimIssuedAt)
	}

	if c.AuthTime != nil {
		ret[ClaimAuthenticationTime] = c.AuthTime.Unix()
	} else {
		delete(ret, ClaimAuthenticationTime)
	}

	if len(c.Nonce) > 0 {
		ret[ClaimNonce] = c.Nonce
	} else {
		delete(ret, ClaimNonce)
	}

	if len(c.AuthenticationContextClassReference) > 0 {
		ret[ClaimAuthenticationContextClassReference] = c.AuthenticationContextClassReference
	} else {
		delete(ret, ClaimAuthenticationContextClassReference)
	}

	if len(c.AuthenticationMethodsReferences) > 0 {
		ret[ClaimAuthenticationMethodsReference] = c.AuthenticationMethodsReferences
	} else {
		delete(ret, ClaimAuthenticationMethodsReference)
	}

	if len(c.AuthorizedParty) > 0 {
		ret[ClaimAuthorizedParty] = c.AuthorizedParty
	} else {
		delete(ret, ClaimAuthorizedParty)
	}

	if len(c.AccessTokenHash) > 0 {
		ret[ClaimAccessTokenHash] = c.AccessTokenHash
	} else {
		delete(ret, ClaimAccessTokenHash)
	}

	if len(c.CodeHash) > 0 {
		ret[ClaimCodeHash] = c.CodeHash
	} else {
		delete(ret, ClaimCodeHash)
	}

	if len(c.StateHash) > 0 {
		ret[ClaimStateHash] = c.StateHash
	} else {
		delete(ret, ClaimStateHash)
	}

	return ret
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c IDTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
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

func (c IDTokenClaims) toNumericDate(key string) (date *NumericDate, err error) {
	var (
		v  any
		ok bool
	)

	if v, ok = c.Extra[key]; !ok {
		return nil, nil
	}

	return toNumericDate(v)
}

func toStringSlice(value any) (values []string, ok bool) {
	switch t := value.(type) {
	case nil:
		ok = true
	case string:
		ok = true

		values = []string{t}
	case []string:
		ok = true

		values = t
	case []any:
		ok = true

	loop:
		for _, tv := range t {
			switch vv := tv.(type) {
			case string:
				values = append(values, vv)
			default:
				ok = false

				break loop
			}
		}
	}

	return values, ok
}

var (
	_ Claims = (*IDTokenClaims)(nil)
)
