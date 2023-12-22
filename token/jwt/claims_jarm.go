package jwt

import (
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/consts"
)

// JARMClaims represent a token's claims.
type JARMClaims struct {
	Issuer    string
	Audience  []string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Extra     map[string]any
}

// ToMap will transform the headers to a map structure
func (c *JARMClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

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

	return ret
}

// FromMap will set the claims based on a mapping
func (c *JARMClaims) FromMap(m map[string]any) {
	c.Extra = make(map[string]any)
	for k, v := range m {
		switch k {
		case consts.ClaimIssuer:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case consts.ClaimJWTID:
			if s, ok := v.(string); ok {
				c.JTI = s
			}
		case consts.ClaimAudience:
			if aud, ok := StringSliceFromMap(v); ok {
				c.Audience = aud
			}
		case consts.ClaimIssuedAt:
			c.IssuedAt = toTime(v, c.IssuedAt)
		case consts.ClaimExpirationTime:
			c.ExpiresAt = toTime(v, c.ExpiresAt)
		default:
			c.Extra[k] = v
		}
	}
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

// ToMapClaims will return a jwt-go MapClaims representation
func (c JARMClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// FromMapClaims will populate claims from a jwt-go MapClaims representation
func (c *JARMClaims) FromMapClaims(mc MapClaims) {
	c.FromMap(mc)
}
