// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/clone"
	"authelia.com/provider/oauth2/internal/consts"
)

// Enum for different types of scope encoding.
type JWTScopeFieldEnum int

const (
	JWTScopeFieldUnset JWTScopeFieldEnum = iota
	JWTScopeFieldList
	JWTScopeFieldString
	JWTScopeFieldBoth
)

type JWTClaimsDefaults struct {
	ExpiresAt time.Time
	IssuedAt  time.Time
	Issuer    string
	Scope     []string
}

type JWTClaimsContainer interface {
	// Sanitize returns a copy of itself with the IssuedAt and NotBefore values cleared.
	Sanitize() JWTClaimsContainer

	// With returns a copy of itself with expiresAt, scope, audience set to the given values.
	With(expiry time.Time, scope, audience []string) JWTClaimsContainer

	// WithDefaults returns a copy of itself with issuedAt and issuer set to the given default values. If those
	// values are already set in the claims, they will not be updated.
	WithDefaults(iat, nbf time.Time, issuer string) JWTClaimsContainer

	// WithScopeField configures how a scope field should be represented in JWT.
	WithScopeField(scopeField JWTScopeFieldEnum) JWTClaimsContainer

	// ToMapClaims returns the claims as a MapClaims type.
	ToMapClaims() MapClaims
}

// NotBeforeJWTClaimsContainer is a JWTClaimsContainer which exposes its NotBefore value.
type NotBeforeJWTClaimsContainer interface {
	// GetNotBefore returns the NotBefore value.
	GetNotBefore() time.Time

	// SetNotBefore sets the NotBefore value.
	SetNotBefore(nbf time.Time)

	JWTClaimsContainer
}

// JWTClaims represent a token's claims.
type JWTClaims struct {
	Subject    string
	Issuer     string
	Audience   []string
	JTI        string
	IssuedAt   time.Time
	NotBefore  time.Time
	ExpiresAt  time.Time
	Scope      []string
	Extra      map[string]any
	ScopeField JWTScopeFieldEnum
}

// Clone returns a deep copy of the claims, or nil if c is nil.
func (c *JWTClaims) Clone() *JWTClaims {
	if c == nil {
		return nil
	}

	cloned := *c

	cloned.Audience = slices.Clone(c.Audience)
	cloned.Scope = slices.Clone(c.Scope)
	cloned.Extra = clone.Map(c.Extra)

	return &cloned
}

// With returns a copy of the claims with expiresAt, scope and audience set to the given values. The receiver is not
// modified.
func (c *JWTClaims) With(expiry time.Time, scope, audience []string) JWTClaimsContainer {
	cloned := c.Clone()

	cloned.ExpiresAt = expiry
	cloned.Scope = scope
	cloned.Audience = audience

	return cloned
}

// Sanitize returns a copy of the claims with IssuedAt and NotBefore cleared. The receiver is not modified.
func (c *JWTClaims) Sanitize() JWTClaimsContainer {
	cloned := c.Clone()

	cloned.IssuedAt = time.Time{}
	cloned.NotBefore = time.Time{}

	return cloned
}

// WithDefaults returns a copy of the claims with IssuedAt, NotBefore and Issuer set to the given values where they are
// unset. The receiver is not modified.
func (c *JWTClaims) WithDefaults(iat, nbf time.Time, issuer string) JWTClaimsContainer {
	cloned := c.Clone()

	if cloned.IssuedAt.IsZero() {
		cloned.IssuedAt = iat
	}

	if cloned.NotBefore.IsZero() {
		cloned.NotBefore = nbf
	}

	if cloned.Issuer == "" {
		cloned.Issuer = issuer
	}

	return cloned
}

// GetNotBefore returns the NotBefore value.
func (c *JWTClaims) GetNotBefore() time.Time {
	return c.NotBefore
}

// SetNotBefore sets the NotBefore value.
func (c *JWTClaims) SetNotBefore(nbf time.Time) {
	c.NotBefore = nbf
}

// WithScopeField sets how the scope is represented in the JWT and returns the claims.
func (c *JWTClaims) WithScopeField(scopeField JWTScopeFieldEnum) JWTClaimsContainer {
	c.ScopeField = scopeField
	return c
}

// ToMap will transform the headers to a map structure
func (c *JWTClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

	if c.Subject != "" {
		ret[ClaimSubject] = c.Subject
	} else {
		delete(ret, ClaimSubject)
	}

	if c.Issuer != "" {
		ret[ClaimIssuer] = c.Issuer
	} else {
		delete(ret, ClaimIssuer)
	}

	if c.JTI != "" {
		ret[ClaimJWTID] = c.JTI
	} else {
		ret[ClaimJWTID] = uuid.New().String()
	}

	// An empty 'aud' is omitted rather than emitted as an empty array. See RFC 7519 Section 4.1.3.
	if len(c.Audience) > 0 {
		ret[ClaimAudience] = c.Audience
	} else {
		delete(ret, ClaimAudience)
	}

	if !c.IssuedAt.IsZero() {
		ret[ClaimIssuedAt] = c.IssuedAt.Unix()
	} else {
		delete(ret, ClaimIssuedAt)
	}

	if !c.NotBefore.IsZero() {
		ret[ClaimNotBefore] = c.NotBefore.Unix()
	} else {
		delete(ret, ClaimNotBefore)
	}

	if !c.ExpiresAt.IsZero() {
		ret[ClaimExpirationTime] = c.ExpiresAt.Unix()
	} else {
		delete(ret, ClaimExpirationTime)
	}

	if c.Scope != nil {
		// ScopeField default (when value is JWTScopeFieldUnset) is the list for backwards compatibility with old versions of oauth2.
		if c.ScopeField == JWTScopeFieldUnset || c.ScopeField == JWTScopeFieldList || c.ScopeField == JWTScopeFieldBoth {
			ret[ClaimScopeNonStandard] = c.Scope
		}
		if c.ScopeField == JWTScopeFieldString || c.ScopeField == JWTScopeFieldBoth {
			ret[ClaimScope] = strings.Join(c.Scope, " ")
		}
	} else {
		delete(ret, ClaimScopeNonStandard)
		delete(ret, ClaimScope)
	}

	return ret
}

// FromMap will set the claims based on a mapping.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *JWTClaims) FromMap(m map[string]any) {
	c.Extra = make(map[string]any)
	for k, v := range m {
		switch k {
		case consts.ClaimJWTID:
			if s, ok := v.(string); ok {
				c.JTI = s
			}
		case consts.ClaimSubject:
			if s, ok := v.(string); ok {
				c.Subject = s
			}
		case consts.ClaimIssuer:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case consts.ClaimAudience:
			if aud, ok := StringSliceFromMap(v); ok {
				c.Audience = aud
			}
		case consts.ClaimIssuedAt:
			c.IssuedAt, _ = toTime(v, c.IssuedAt)
		case consts.ClaimNotBefore:
			c.NotBefore, _ = toTime(v, c.NotBefore)
		case consts.ClaimExpirationTime:
			c.ExpiresAt, _ = toTime(v, c.ExpiresAt)
		case consts.ClaimScopeNonStandard:
			switch s := v.(type) {
			case []string:
				c.Scope = s

				switch c.ScopeField {
				case JWTScopeFieldString:
					c.ScopeField = JWTScopeFieldBoth
				case JWTScopeFieldUnset:
					c.ScopeField = JWTScopeFieldList
				default:
					break
				}
			case []any:
				c.Scope = make([]string, len(s))

				for i, vi := range s {
					if s, ok := vi.(string); ok {
						c.Scope[i] = s
					}
				}

				switch c.ScopeField {
				case JWTScopeFieldString:
					c.ScopeField = JWTScopeFieldBoth
				case JWTScopeFieldUnset:
					c.ScopeField = JWTScopeFieldList
				default:
					break
				}
			}
		case consts.ClaimScope:
			if s, ok := v.(string); ok {
				c.Scope = strings.Split(s, " ")

				switch c.ScopeField {
				case JWTScopeFieldList:
					c.ScopeField = JWTScopeFieldBoth
				case JWTScopeFieldUnset:
					c.ScopeField = JWTScopeFieldString
				default:
					break
				}
			}
		default:
			c.Extra[k] = v
		}
	}
}

//nolint:unparam
func toTime(v any, def time.Time) (t time.Time, ok bool) {
	t = def

	var value int64

	if value, ok = toInt64(v); ok {
		t = time.Unix(value, 0).UTC()
	}

	return
}

func toInt64(v any) (val int64, ok bool) {
	var err error

	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int32:
		return int64(t), true
	case int:
		return int64(t), true
	case json.Number:
		if val, err = t.Int64(); err == nil {
			return val, true
		}

		var valf float64

		if valf, err = t.Float64(); err != nil {
			return 0, false
		}

		return int64(valf), true
	}

	return 0, false
}

func toNumericDate(v any) (date *NumericDate, err error) {
	switch value := v.(type) {
	case nil:
		return nil, nil
	case *NumericDate:
		return value, nil
	case float64:
		if value == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(value), nil
	case int64:
		if value == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(float64(value)), nil
	case int32:
		if value == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(float64(value)), nil
	case int:
		if value == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(float64(value)), nil
	case json.Number:
		vv, _ := value.Float64()

		return newNumericDateFromSeconds(vv), nil
	}

	return nil, newError("value has invalid type", ErrInvalidType)
}

// Add will add a key-value pair to the extra field
func (c *JWTClaims) Add(key string, value any) {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}

	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c JWTClaims) Get(key string) any {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c JWTClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// FromMapClaims will populate claims from a jwt-go MapClaims representation
func (c *JWTClaims) FromMapClaims(mc MapClaims) {
	c.FromMap(mc)
}
