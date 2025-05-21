package jwt

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	jjson "github.com/go-jose/go-jose/v4/json"
	"github.com/google/uuid"

	"authelia.com/provider/oauth2/x/errorsx"
)

func NewLogoutTokenClaims(subject string, audience []string, sid string, extra map[string]any) (claims *LogoutTokenClaims) {
	claims = &LogoutTokenClaims{
		Subject:   subject,
		Audience:  audience,
		SessionID: sid,
		Extra:     extra,
		IssuedAt:  Now(),
	}

	claims.Events.BackChannelLogout = make(map[string]any)

	return claims
}

// LogoutTokenClaims represent the claims used in open id connect requests
type LogoutTokenClaims struct {
	JTI            string       `json:"jti"`
	Issuer         string       `json:"iss"`
	Subject        string       `json:"sub,omitempty"`
	Audience       []string     `json:"aud"`
	IssuedAt       *NumericDate `json:"iat"`
	ExpirationTime *NumericDate `json:"exp"`
	Events         struct {
		BackChannelLogout map[string]any `json:"http://schemas.openid.net/event/backchannel-logout"`
	} `json:"events"`
	SessionID string         `json:"sid,omitempty"`
	Extra     map[string]any `json:"ext,omitempty"`
}

func (c *LogoutTokenClaims) GetExpirationTime() (exp *NumericDate, err error) {
	return c.ExpirationTime, nil
}

func (c *LogoutTokenClaims) GetIssuedAt() (iat *NumericDate, err error) {
	return c.IssuedAt, nil
}

// A logout-token never contains an nbf claim, so we simply return nil, nil.
func (c *LogoutTokenClaims) GetNotBefore() (*NumericDate, error) {
	return nil, nil
}

func (c *LogoutTokenClaims) GetIssuer() (iss string, err error) {
	return c.Issuer, nil
}

func (c *LogoutTokenClaims) GetSubject() (sub string, err error) {
	return c.Subject, nil
}

func (c *LogoutTokenClaims) GetAudience() (aud ClaimStrings, err error) {
	return c.Audience, nil
}

//nolint:gocyclo
func (c LogoutTokenClaims) Valid(opts ...ClaimValidationOption) (err error) {
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

	if date, err = c.GetIssuedAt(); !validDate(validInt64Past, now, vopts.iatRequired, date, err) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
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
			vErr.Errors |= ValidationErrorSubject
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

func (c *LogoutTokenClaims) GetExpirationTimeSafe() time.Time {
	if c.ExpirationTime == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.ExpirationTime.UTC()
}

func (c *LogoutTokenClaims) GetIssuedAtSafe() time.Time {
	if c.IssuedAt == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.IssuedAt.UTC()
}

// UnmarshalJSON handles the JSON unmarshalling for the LogoutTokenClaims.
//
//nolint:gocyclo
func (c *LogoutTokenClaims) UnmarshalJSON(data []byte) error {
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
		case ClaimSessionID:
			c.SessionID, ok = value.(string)
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
		case ClaimNonce:
			return fmt.Errorf("nonce is not a valid logout token claim")
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
func (c *LogoutTokenClaims) ToMap() map[string]any {
	var ret = Copy(c.Extra)

	if _, ok := ret[ClaimNonce]; ok {
		delete(ret, ClaimNonce)
	}

	if c.JTI != "" {
		ret[ClaimJWTID] = c.JTI
	} else {
		ret[ClaimJWTID] = uuid.New().String()
	}

	if c.Issuer != "" {
		ret[ClaimIssuer] = c.Issuer
	} else {
		delete(ret, ClaimIssuer)
	}

	if c.Subject != "" {
		ret[ClaimSubject] = c.Subject
	} else {
		delete(ret, ClaimSubject)
	}

	if c.SessionID != "" {
		ret[ClaimSessionID] = c.SessionID
	} else {
		delete(ret, ClaimSessionID)
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

	ret[ClaimEvents] = map[string]any{
		ClaimEventBackChannelLogout: map[string]any{},
	}

	return ret
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c LogoutTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// Add will add a key-value pair to the extra field
func (c *LogoutTokenClaims) Add(key string, value any) {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}

	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c *LogoutTokenClaims) Get(key string) any {
	return c.ToMap()[key]
}

var (
	_ Claims = (*LogoutTokenClaims)(nil)
)
