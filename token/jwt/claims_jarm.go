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
		ret[ClaimAudience] = c.Audience
	} else {
		ret[ClaimAudience] = []string{}
	}

	if !c.IssuedAt.IsZero() {
		ret[ClaimIssuedAt] = c.IssuedAt.Unix()
	} else {
		delete(ret, ClaimIssuedAt)
	}

	if !c.ExpiresAt.IsZero() {
		ret[ClaimExpirationTime] = c.ExpiresAt.Unix()
	} else {
		delete(ret, ClaimExpirationTime)
	}

	return ret
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
		case consts.ClaimIssuedAt:
			c.IssuedAt, _ = toTime(v, c.IssuedAt)
		case consts.ClaimExpirationTime:
			c.ExpiresAt, _ = toTime(v, c.ExpiresAt)
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
