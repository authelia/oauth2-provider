// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	. "authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenClaims_MapClaimsValid(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *IDTokenClaims
		wantErr bool
	}{
		{
			name:    "ShouldPassFutureExpiration",
			claims:  &IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))},
			wantErr: false,
		},
		{
			name:    "ShouldFailPastExpiration",
			claims:  &IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.claims.ToMapClaims().Valid()

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIDTokenClaims_ToMapClaimsSetsID(t *testing.T) {
	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()[ClaimJWTID])
}

func TestIDTokenClaims_ToMap(t *testing.T) {
	base := &IDTokenClaims{
		JTI:                                 "foo-id",
		Subject:                             "peter",
		IssuedAt:                            Now(),
		Issuer:                              "authelia",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		AuthTime:                            Now(),
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	testCases := []struct {
		name     string
		mutate   func(c *IDTokenClaims)
		expected func(c *IDTokenClaims) map[string]any
	}{
		{
			name:   "ShouldOmitNonceWhenEmpty",
			mutate: func(c *IDTokenClaims) {},
			expected: func(c *IDTokenClaims) map[string]any {
				return map[string]any{
					ClaimJWTID:              c.JTI,
					ClaimSubject:            c.Subject,
					ClaimIssuedAt:           c.IssuedAt.Unix(),
					ClaimIssuer:             c.Issuer,
					ClaimAudience:           c.Audience,
					ClaimExpirationTime:     c.ExpirationTime.Unix(),
					"foo":                   c.Extra["foo"],
					"baz":                   c.Extra["baz"],
					ClaimAccessTokenHash:    c.AccessTokenHash,
					ClaimCodeHash:           c.CodeHash,
					ClaimStateHash:          c.StateHash,
					ClaimAuthenticationTime: c.AuthTime.Unix(),
					consts.ClaimAuthenticationContextClassReference: c.AuthenticationContextClassReference,
					consts.ClaimAuthenticationMethodsReference:      c.AuthenticationMethodsReferences,
				}
			},
		},
		{
			name: "ShouldIncludeNonceWhenSet",
			mutate: func(c *IDTokenClaims) {
				c.Nonce = "foobar"
			},
			expected: func(c *IDTokenClaims) map[string]any {
				return map[string]any{
					consts.ClaimJWTID:              c.JTI,
					consts.ClaimSubject:            c.Subject,
					consts.ClaimIssuedAt:           c.IssuedAt.Unix(),
					consts.ClaimIssuer:             c.Issuer,
					consts.ClaimAudience:           c.Audience,
					consts.ClaimExpirationTime:     c.ExpirationTime.Unix(),
					"foo":                          c.Extra["foo"],
					"baz":                          c.Extra["baz"],
					consts.ClaimAccessTokenHash:    c.AccessTokenHash,
					consts.ClaimCodeHash:           c.CodeHash,
					consts.ClaimStateHash:          c.StateHash,
					consts.ClaimAuthenticationTime: c.AuthTime.Unix(),
					consts.ClaimAuthenticationContextClassReference: c.AuthenticationContextClassReference,
					consts.ClaimAuthenticationMethodsReference:      c.AuthenticationMethodsReferences,
					consts.ClaimNonce: c.Nonce,
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := *base
			tc.mutate(&c)
			assert.Equal(t, tc.expected(&c), c.ToMap())
		})
	}
}

func TestIDTokenClaims_FromMap(t *testing.T) {
	expected := &IDTokenClaims{
		JTI:                                 "foo-id",
		Issuer:                              "authelia",
		Subject:                             "peter",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:                            Now(),
		AuthTime:                            Now(),
		Nonce:                               "nonce-value",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		AuthorizedParty:                     "client-id",
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	m := map[string]any{
		ClaimJWTID:                               expected.JTI,
		ClaimIssuer:                              expected.Issuer,
		ClaimSubject:                             expected.Subject,
		ClaimAudience:                            expected.Audience,
		ClaimExpirationTime:                      expected.ExpirationTime.Unix(),
		ClaimIssuedAt:                            expected.IssuedAt.Unix(),
		ClaimAuthenticationTime:                  expected.AuthTime.Unix(),
		ClaimNonce:                               expected.Nonce,
		ClaimAuthenticationContextClassReference: expected.AuthenticationContextClassReference,
		ClaimAuthenticationMethodsReference:      expected.AuthenticationMethodsReferences,
		ClaimAuthorizedParty:                     expected.AuthorizedParty,
		ClaimAccessTokenHash:                     expected.AccessTokenHash,
		ClaimCodeHash:                            expected.CodeHash,
		ClaimStateHash:                           expected.StateHash,
		"foo":                                    "bar",
		"baz":                                    "bar",
	}

	testCases := []struct {
		name string
		fn   func(c *IDTokenClaims)
	}{
		{
			name: "ShouldDecodeFromMap",
			fn: func(c *IDTokenClaims) {
				c.FromMap(m)
			},
		},
		{
			name: "ShouldDecodeFromMapClaims",
			fn: func(c *IDTokenClaims) {
				c.FromMapClaims(MapClaims(m))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual IDTokenClaims
			tc.fn(&actual)
			assert.Equal(t, expected, &actual)
		})
	}
}

func TestIDTokenClaims_RoundTrip(t *testing.T) {
	original := &IDTokenClaims{
		JTI:                                 "foo-id",
		Issuer:                              "authelia",
		Subject:                             "peter",
		Audience:                            []string{"tests"},
		ExpirationTime:                      NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:                            Now(),
		AuthTime:                            Now(),
		Nonce:                               "nonce-value",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		AuthorizedParty:                     "client-id",
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		StateHash:                           "boofar",
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	var roundTripped IDTokenClaims

	roundTripped.FromMap(original.ToMap())
	assert.Equal(t, original, &roundTripped)

	originalMap := original.ToMap()
	assert.Equal(t, originalMap, roundTripped.ToMap())
}

func TestIDTokenClaims_FromMapExtra(t *testing.T) {
	m := map[string]any{
		ClaimJWTID:   "foo-id",
		ClaimSubject: "peter",
		ClaimExtra: map[string]any{
			"foo": "bar",
		},
	}

	var actual IDTokenClaims

	actual.FromMap(m)
	assert.Equal(t, "foo-id", actual.JTI)
	assert.Equal(t, "peter", actual.Subject)
	assert.Equal(t, map[string]any{"foo": "bar"}, actual.Extra)
}

func TestIDTokenClaims_Getters(t *testing.T) {
	exp := NewNumericDate(time.Now().Add(time.Hour))
	iat := NewNumericDate(time.Now())
	nbf := NewNumericDate(time.Now().Add(-time.Minute))

	claims := &IDTokenClaims{
		Issuer:         "authelia",
		Subject:        "peter",
		Audience:       []string{"tests"},
		ExpirationTime: exp,
		IssuedAt:       iat,
		Extra: map[string]any{
			ClaimNotBefore: nbf.Unix(),
		},
	}

	actualExp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.Equal(t, exp, actualExp)

	actualIat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	assert.Equal(t, iat, actualIat)

	actualNbf, err := claims.GetNotBefore()
	require.NoError(t, err)
	assert.Equal(t, nbf.Unix(), actualNbf.Unix())

	iss, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "authelia", iss)

	sub, err := claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "peter", sub)

	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Equal(t, ClaimStrings{"tests"}, aud)
}

func TestIDTokenClaims_SafeGetters(t *testing.T) {
	zero := time.Unix(0, 0).UTC()
	now := time.Now().UTC().Truncate(time.Second)

	testCases := []struct {
		name    string
		claims  *IDTokenClaims
		expExp  time.Time
		expIat  time.Time
		expAuth time.Time
	}{
		{
			name:    "ShouldReturnZeroWhenNotSet",
			claims:  &IDTokenClaims{},
			expExp:  zero,
			expIat:  zero,
			expAuth: zero,
		},
		{
			name: "ShouldReturnValuesWhenSet",
			claims: &IDTokenClaims{
				ExpirationTime: NewNumericDate(now),
				IssuedAt:       NewNumericDate(now),
				AuthTime:       NewNumericDate(now),
			},
			expExp:  now,
			expIat:  now,
			expAuth: now,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expExp, tc.claims.GetExpirationTimeSafe())
			assert.Equal(t, tc.expIat, tc.claims.GetIssuedAtSafe())
			assert.Equal(t, tc.expAuth, tc.claims.GetAuthTimeSafe())
		})
	}
}

func TestIDTokenClaims_Add(t *testing.T) {
	t.Run("ShouldInitializeExtraWhenNil", func(t *testing.T) {
		c := &IDTokenClaims{}
		c.Add("foo", "bar")
		assert.Equal(t, "bar", c.Extra["foo"])
	})

	t.Run("ShouldAddToExistingExtra", func(t *testing.T) {
		c := &IDTokenClaims{Extra: map[string]any{"existing": 1}}
		c.Add("foo", "bar")
		assert.Equal(t, 1, c.Extra["existing"])
		assert.Equal(t, "bar", c.Extra["foo"])
	})
}

func TestIDTokenClaims_Get(t *testing.T) {
	c := &IDTokenClaims{
		JTI:     "id-1",
		Subject: "peter",
		Extra: map[string]any{
			"foo": "bar",
		},
	}

	assert.Equal(t, "id-1", c.Get(ClaimJWTID))
	assert.Equal(t, "peter", c.Get(ClaimSubject))
	assert.Equal(t, "bar", c.Get("foo"))
	assert.Nil(t, c.Get("missing"))
}

func TestIDTokenClaims_Valid(t *testing.T) {
	fixedTime := time.Unix(1700000000, 0).UTC()
	future := NewNumericDate(fixedTime.Add(time.Hour))
	past := NewNumericDate(fixedTime.Add(-time.Hour))
	timeFunc := func() time.Time { return fixedTime }

	testCases := []struct {
		name string
		have *IDTokenClaims
		opts []ClaimValidationOption
		errs uint32
		err  string
	}{
		{
			name: "ShouldPassEmpty",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
		},
		{
			name: "ShouldFailExpiredEXP",
			have: &IDTokenClaims{ExpirationTime: past},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
			errs: ValidationErrorExpired,
			err:  "Token is expired",
		},
		{
			name: "ShouldFailIATInFuture",
			have: &IDTokenClaims{IssuedAt: future},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
			errs: ValidationErrorIssuedAt,
			err:  "Token used before issued",
		},
		{
			name: "ShouldFailNBFInFuture",
			have: &IDTokenClaims{Extra: map[string]any{ClaimNotBefore: future.Unix()}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
			errs: ValidationErrorNotValidYet,
			err:  "Token is not valid yet",
		},
		{
			name: "ShouldFailRequireEXP",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateRequireExpiresAt()},
			errs: ValidationErrorExpired,
			err:  "Token is expired",
		},
		{
			name: "ShouldFailRequireIAT",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateRequireIssuedAt()},
			errs: ValidationErrorIssuedAt,
			err:  "Token used before issued",
		},
		{
			name: "ShouldFailRequireNBF",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateRequireNotBefore()},
			errs: ValidationErrorNotValidYet,
			err:  "Token is not valid yet",
		},
		{
			name: "ShouldPassIssuer",
			have: &IDTokenClaims{Issuer: "authelia"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
		},
		{
			name: "ShouldFailIssuerMismatch",
			have: &IDTokenClaims{Issuer: "wrong"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
			errs: ValidationErrorIssuer,
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldFailIssuerAbsentRequired",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
			errs: ValidationErrorIssuer,
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldPassIssuerAbsentNotRequired",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia"), ValidateDoNotRequireIssuer()},
		},
		{
			name: "ShouldPassSubject",
			have: &IDTokenClaims{Subject: "peter"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
		},
		{
			name: "ShouldFailSubjectMismatch",
			have: &IDTokenClaims{Subject: "wrong"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
			errs: ValidationErrorSubject,
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldFailSubjectAbsent",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
			errs: ValidationErrorSubject,
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldPassAuthorizedParty",
			have: &IDTokenClaims{AuthorizedParty: "client-id"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAuthorizedParty("client-id")},
		},
		{
			name: "ShouldFailAuthorizedPartyMismatch",
			have: &IDTokenClaims{AuthorizedParty: "other"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAuthorizedParty("client-id")},
			errs: ValidationErrorAuthorizedParty,
			err:  "Token has invalid azp claim",
		},
		{
			name: "ShouldPassAudienceAny",
			have: &IDTokenClaims{Audience: []string{"a", "b"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAny("b")},
		},
		{
			name: "ShouldFailAudienceAnyNoMatch",
			have: &IDTokenClaims{Audience: []string{"x"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAny("a")},
			errs: ValidationErrorAudience,
			err:  "Token has invalid audience",
		},
		{
			name: "ShouldFailAudienceAnyAbsentRequired",
			have: &IDTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAny("a")},
			errs: ValidationErrorAudience,
			err:  "Token has invalid audience",
		},
		{
			name: "ShouldPassAudienceAll",
			have: &IDTokenClaims{Audience: []string{"a", "b"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAll("a", "b")},
		},
		{
			name: "ShouldFailAudienceAllMissing",
			have: &IDTokenClaims{Audience: []string{"a"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAll("a", "b")},
			errs: ValidationErrorAudience,
			err:  "Token has invalid audience",
		},
		{
			name: "ShouldUseDefaultTimeFuncWhenNone",
			have: &IDTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))},
			errs: ValidationErrorExpired,
			err:  "Token is expired",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.Valid(tc.opts...)

			if tc.errs == 0 {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, err, tc.err)

			ve, ok := err.(*ValidationError)
			require.True(t, ok)
			assert.Equal(t, tc.errs, ve.Errors&tc.errs)
		})
	}
}

func TestIDTokenClaims_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name    string
		raw     string
		expect  func(t *testing.T, c *IDTokenClaims)
		wantErr string
	}{
		{
			name: "ShouldDecodeAllStandardClaims",
			raw: `{
				"jti":"id-1",
				"iss":"authelia",
				"sub":"peter",
				"aud":["tests"],
				"exp":1700003600,
				"iat":1700000000,
				"auth_time":1700000000,
				"nonce":"n",
				"acr":"acr",
				"amr":["amr"],
				"azp":"client-id",
				"at_hash":"at",
				"c_hash":"c",
				"s_hash":"s"
			}`,
			expect: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, "authelia", c.Issuer)
				assert.Equal(t, "peter", c.Subject)
				assert.Equal(t, []string{"tests"}, c.Audience)
				assert.Equal(t, int64(1700003600), c.ExpirationTime.Unix())
				assert.Equal(t, int64(1700000000), c.IssuedAt.Unix())
				assert.Equal(t, int64(1700000000), c.AuthTime.Unix())
				assert.Equal(t, "n", c.Nonce)
				assert.Equal(t, "acr", c.AuthenticationContextClassReference)
				assert.Equal(t, []string{"amr"}, c.AuthenticationMethodsReferences)
				assert.Equal(t, "client-id", c.AuthorizedParty)
				assert.Equal(t, "at", c.AccessTokenHash)
				assert.Equal(t, "c", c.CodeHash)
				assert.Equal(t, "s", c.StateHash)
			},
		},
		{
			name: "ShouldRouteUnknownClaimsToExtra",
			raw:  `{"jti":"id-1","custom":"value"}`,
			expect: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, "value", c.Extra["custom"])
			},
		},
		{
			name: "ShouldDecodeExtraClaimAsMap",
			raw:  `{"jti":"id-1","ext":{"foo":"bar"}}`,
			expect: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, map[string]any{"foo": "bar"}, c.Extra)
			},
		},
		{
			name: "ShouldDecodeAudienceAsSingleString",
			raw:  `{"aud":"tests"}`,
			expect: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, []string{"tests"}, c.Audience)
			},
		},
		{
			name: "ShouldDecodeNullAudienceAsNil",
			raw:  `{"jti":"id-1","aud":null}`,
			expect: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Nil(t, c.Audience)
			},
		},
		{
			name:    "ShouldErrorOnAudienceWithNonStringElement",
			raw:     `{"aud":[1,2]}`,
			wantErr: "claim aud with value [1 2] could not be decoded",
		},
		{
			name:    "ShouldErrorOnInvalidJSON",
			raw:     `not-json`,
			wantErr: "invalid character",
		},
		{
			name:    "ShouldErrorOnUndecodableStringClaim",
			raw:     `{"sub":123}`,
			wantErr: "claim sub with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableNumericDate",
			raw:     `{"exp":"not-a-time"}`,
			wantErr: "claim exp with value not-a-time could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableAudience",
			raw:     `{"aud":123}`,
			wantErr: "claim aud with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableExtra",
			raw:     `{"ext":"not-a-map"}`,
			wantErr: "claim ext with value not-a-map could not be decoded",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c IDTokenClaims

			err := json.Unmarshal([]byte(tc.raw), &c)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, err)

			if tc.expect != nil {
				tc.expect(t, &c)
			}
		})
	}

	t.Run("ShouldErrorOnDirectInvalidJSON", func(t *testing.T) {
		var c IDTokenClaims

		require.Error(t, c.UnmarshalJSON([]byte(`not-json`)))
	})
}
