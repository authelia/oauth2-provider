package jwt

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

func NewJARMClaims(issuer string, aud ClaimStrings, lifespan time.Duration) *JARMClaims {
	now := time.Now()

	return &JARMClaims{
		Issuer:         issuer,
		Audience:       aud,
		JTI:            uuid.NewString(),
		IssuedAt:       NewNumericDate(now),
		ExpirationTime: NewNumericDate(now.Add(lifespan)),
		Extra:          map[string]any{},
	}
}

// JARMClaims represent a token's claims.
type JARMClaims struct {
	Issuer         string         `json:"iss"`
	Audience       ClaimStrings   `json:"aud"`
	JTI            string         `json:"jti"`
	IssuedAt       *NumericDate   `json:"iat,omitempty"`
	ExpirationTime *NumericDate   `json:"exp,omitempty"`
	Extra          map[string]any `json:"-"`
}

func (c *JARMClaims) GetExpirationTime() (exp *NumericDate, err error) {
	return c.ExpirationTime, nil
}

func (c *JARMClaims) GetIssuedAt() (iat *NumericDate, err error) {
	return c.IssuedAt, nil
}

func (c *JARMClaims) GetNotBefore() (nbf *NumericDate, err error) {
	return c.toNumericDate(ClaimNotBefore)
}

func (c *JARMClaims) GetIssuer() (iss string, err error) {
	return c.Issuer, nil
}

func (c *JARMClaims) GetSubject() (sub string, err error) {
	return c.toString(ClaimIssuer)
}

func (c *JARMClaims) GetAudience() (aud ClaimStrings, err error) {
	return c.Audience, nil
}

func (c *JARMClaims) Valid(opts ...ClaimValidationOption) (err error) {
	return nil
}

// ToMap will transform the headers to a map structure
func (c *JARMClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

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

	if len(c.Audience) > 0 {
		ret[ClaimAudience] = []string(c.Audience)
	} else {
		ret[ClaimAudience] = []string{}
	}

	if c.IssuedAt != nil {
		ret[ClaimIssuedAt] = c.IssuedAt.Unix()
	} else {
		delete(ret, ClaimIssuedAt)
	}

	if c.ExpirationTime != nil {
		ret[ClaimExpirationTime] = c.ExpirationTime.Unix()
	} else {
		delete(ret, ClaimExpirationTime)
	}

	return ret
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c JARMClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// FromMap will set the claims based on a mapping
func (c *JARMClaims) FromMap(m map[string]any) {
	c.Extra = make(map[string]any)
	for k, v := range m {
		switch k {
		case ClaimIssuer:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case ClaimJWTID:
			if s, ok := v.(string); ok {
				c.JTI = s
			}
		case ClaimAudience:
			if aud, ok := StringSliceFromMap(v); ok {
				c.Audience = aud
			}
		case ClaimIssuedAt:
			c.IssuedAt, _ = toNumericDate(v)
		case ClaimExpirationTime:
			c.ExpirationTime, _ = toNumericDate(v)
		default:
			c.Extra[k] = v
		}
	}
}

// FromMapClaims will populate claims from a jwt-go MapClaims representation
func (c *JARMClaims) FromMapClaims(mc MapClaims) {
	c.FromMap(mc)
}

// Add will add a key-value pair to the extra field
func (c *JARMClaims) Add(key string, value any) {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}

	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c JARMClaims) Get(key string) any {
	return c.ToMap()[key]
}

func (c JARMClaims) toNumericDate(key string) (date *NumericDate, err error) {
	var (
		v  any
		ok bool
	)

	if v, ok = c.Extra[key]; !ok {
		return nil, nil
	}

	return toNumericDate(v)
}

func (c JARMClaims) toString(key string) (value string, err error) {
	var (
		ok  bool
		raw any
	)

	if raw, ok = c.Extra[key]; !ok {
		return "", nil
	}

	if value, ok = raw.(string); !ok {
		return "", newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
	}

	return value, nil
}

var (
	_ Claims = (*JARMClaims)(nil)
)
