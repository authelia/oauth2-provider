// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	jjson "authelia.com/provider/jose/json"

	"authelia.com/provider/oauth2/x/errorsx"
)

// NewSecurityEventTokenClaims returns SecurityEventTokenClaims for exactly one event about the subject, with a
// generated 'jti' and an 'iat' of the current time (RFC 8417 §2.2, SSF 1.0 §4). The 'iss', 'aud' and event type are
// required and the txn is optional. A caller reusing a 'jti' sets JTI on the result.
func NewSecurityEventTokenClaims(issuer string, audience []string, subject *SubjectIdentifier, event SecurityEvent, txn string) (claims *SecurityEventTokenClaims, err error) {
	if issuer == "" {
		return nil, fmt.Errorf("%w: the 'iss' claim is required", ErrInvalidSecurityEvent)
	}

	if len(audience) == 0 || slices.Contains(audience, "") {
		return nil, fmt.Errorf("%w: the 'aud' claim is required", ErrInvalidSecurityEvent)
	}

	if event == nil {
		return nil, fmt.Errorf("%w: the event is nil", ErrInvalidSecurityEvent)
	}

	if event.SecurityEventType() == "" {
		return nil, fmt.Errorf("%w: the event type is required", ErrInvalidSecurityEvent)
	}

	if err = subject.Validate(); err != nil {
		return nil, err
	}

	if v, ok := event.(interface{ Validate() error }); ok {
		if err = v.Validate(); err != nil {
			return nil, err
		}
	}

	var (
		data    []byte
		payload map[string]any
	)

	if data, err = json.Marshal(event); err != nil {
		return nil, errorsx.WithStack(err)
	}

	decoder := jjson.NewDecoder(bytes.NewReader(data))
	decoder.SetNumberType(jjson.UnmarshalIntOrFloat)

	if err = decoder.Decode(&payload); err != nil {
		return nil, errorsx.WithStack(err)
	}

	if payload == nil {
		payload = map[string]any{}
	}

	return &SecurityEventTokenClaims{
		JTI:               uuid.New().String(),
		Issuer:            issuer,
		Audience:          audience,
		IssuedAt:          Now(),
		SubjectIdentifier: subject,
		Transaction:       txn,
		Events:            map[string]any{event.SecurityEventType(): payload},
	}, nil
}

// SecurityEventTokenClaims represent the claims of a Security Event Token (RFC 8417 §2.2). The 'sub' and 'exp' claims
// are prohibited (SSF 1.0 §4). Events holds the event payload keyed by event type URI, which is also the decoded form
// of a parsed token.
type SecurityEventTokenClaims struct {
	JTI               string             `json:"jti"`
	Issuer            string             `json:"iss"`
	Audience          []string           `json:"aud,omitempty"`
	IssuedAt          *NumericDate       `json:"iat"`
	SubjectIdentifier *SubjectIdentifier `json:"sub_id,omitempty"`
	Transaction       string             `json:"txn,omitempty"`
	Events            map[string]any     `json:"events"`

	hasSubject    bool
	hasExpiration bool
}

// GetExpirationTime returns nil as a SET has no 'exp' claim.
func (c *SecurityEventTokenClaims) GetExpirationTime() (exp *NumericDate, err error) {
	return nil, nil
}

// GetIssuedAt returns the 'iat' claim.
func (c *SecurityEventTokenClaims) GetIssuedAt() (iat *NumericDate, err error) {
	return c.IssuedAt, nil
}

// GetNotBefore returns nil as a SET has no 'nbf' claim.
func (c *SecurityEventTokenClaims) GetNotBefore() (nbf *NumericDate, err error) {
	return nil, nil
}

// GetIssuer returns the 'iss' claim.
func (c *SecurityEventTokenClaims) GetIssuer() (iss string, err error) {
	return c.Issuer, nil
}

// GetSubject returns an empty string as a SET has no 'sub' claim.
func (c *SecurityEventTokenClaims) GetSubject() (sub string, err error) {
	return "", nil
}

// GetAudience returns the 'aud' claim.
func (c *SecurityEventTokenClaims) GetAudience() (aud ClaimStrings, err error) {
	return c.Audience, nil
}

// Valid validates the 'iat' claim, and the 'iss' and 'aud' claims when the respective option is provided. It rejects
// a token with a 'sub' or 'exp' claim (SSF 1.0 §4), without exactly one event (SSF 1.0 §4), without an 'iss' claim or
// without an 'aud', 'jti' or 'iat' claim, or with an invalid 'sub_id' claim.
//
//nolint:gocyclo
func (c SecurityEventTokenClaims) Valid(opts ...ClaimValidationOption) (err error) {
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

	if c.hasSubject {
		vErr.Inner = errors.New("Token has a prohibited sub claim")
		vErr.Errors |= ValidationErrorSubject
	}

	if c.hasExpiration {
		vErr.Inner = errors.New("Token has a prohibited exp claim")
		vErr.Errors |= ValidationErrorExpired
	}

	if len(c.Events) != 1 {
		vErr.Inner = errors.New("Token must have exactly one event")
		vErr.Errors |= ValidationErrorClaimsInvalid
	}

	if err = c.SubjectIdentifier.Validate(); err != nil {
		vErr.Inner = err
		vErr.Errors |= ValidationErrorClaimsInvalid
	}

	if c.Issuer == "" {
		vErr.Inner = errors.New("Token has invalid issuer")
		vErr.Errors |= ValidationErrorIssuer
	}

	if len(c.Audience) == 0 {
		vErr.Inner = errors.New("Token has invalid audience")
		vErr.Errors |= ValidationErrorAudience
	}

	if c.JTI == "" {
		vErr.Inner = errors.New("Token has invalid jti")
		vErr.Errors |= ValidationErrorId
	}

	var date *NumericDate

	if date, err = c.GetIssuedAt(); !validDate(validInt64Past, now+int64(vopts.clockSkew/time.Second), true, date, err) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if len(vopts.iss) != 0 && !validString(c.Issuer, vopts.iss, !vopts.issNotRequired) {
		vErr.Inner = errors.New("Token has invalid issuer")
		vErr.Errors |= ValidationErrorIssuer
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

// GetIssuedAtSafe returns the 'iat' claim as a UTC time, or the Unix epoch if the claim is unset.
func (c *SecurityEventTokenClaims) GetIssuedAtSafe() time.Time {
	if c.IssuedAt == nil {
		return time.Unix(0, 0).UTC()
	}

	return c.IssuedAt.UTC()
}

// UnmarshalJSON handles the JSON unmarshalling for the SecurityEventTokenClaims. Claims other than those of a SET are
// discarded.
//
//nolint:gocyclo
func (c *SecurityEventTokenClaims) UnmarshalJSON(data []byte) (err error) {
	claims := MapClaims{}

	decoder := jjson.NewDecoder(bytes.NewReader(data))
	decoder.SetNumberType(jjson.UnmarshalIntOrFloat)

	if err = decoder.Decode(&claims); err != nil {
		return errorsx.WithStack(err)
	}

	*c = SecurityEventTokenClaims{}

	var ok bool

	for claim, value := range claims {
		ok = true

		switch claim {
		case ClaimJWTID:
			c.JTI, ok = value.(string)
		case ClaimIssuer:
			c.Issuer, ok = value.(string)
		case ClaimAudience:
			c.Audience, ok = toStringSlice(value)
		case ClaimIssuedAt:
			if c.IssuedAt, err = toNumericDate(value); err != nil {
				ok = false
			}
		case ClaimTransaction:
			c.Transaction, ok = value.(string)
		case ClaimEvents:
			c.Events, ok = value.(map[string]any)
		case ClaimSubjectIdentifier:
			var raw []byte

			if raw, err = json.Marshal(value); err != nil {
				return errorsx.WithStack(err)
			}

			c.SubjectIdentifier = &SubjectIdentifier{}

			if err = json.Unmarshal(raw, c.SubjectIdentifier); err != nil {
				ok = false
			}
		case ClaimSubject:
			c.hasSubject = true
		case ClaimExpirationTime:
			c.hasExpiration = true
		}

		if !ok {
			return fmt.Errorf("claim %s with value %v could not be decoded", claim, value)
		}
	}

	return nil
}

// ToMap will transform the claims to a map structure. The 'sub' and 'exp' claims are never present.
func (c *SecurityEventTokenClaims) ToMap() map[string]any {
	ret := map[string]any{}

	if c.JTI != "" {
		ret[ClaimJWTID] = c.JTI
	}

	if c.Issuer != "" {
		ret[ClaimIssuer] = c.Issuer
	}

	if len(c.Audience) > 0 {
		ret[ClaimAudience] = c.Audience
	}

	if c.IssuedAt != nil {
		ret[ClaimIssuedAt] = c.IssuedAt.Unix()
	}

	if c.SubjectIdentifier != nil {
		ret[ClaimSubjectIdentifier] = c.SubjectIdentifier
	}

	if c.Transaction != "" {
		ret[ClaimTransaction] = c.Transaction
	}

	ret[ClaimEvents] = Copy(c.Events)

	return ret
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c SecurityEventTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// Add is a no-op as a SET has no extra claims.
func (c *SecurityEventTokenClaims) Add(key string, value any) {}

// Get will get a value from the claims map based on a given key
func (c *SecurityEventTokenClaims) Get(key string) any {
	return c.ToMap()[key]
}

var (
	_ Claims = (*SecurityEventTokenClaims)(nil)
)
