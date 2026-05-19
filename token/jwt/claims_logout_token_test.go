package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	. "authelia.com/provider/oauth2/token/jwt"
)

func TestLogoutTokenClaims_MapClaimsValid(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *LogoutTokenClaims
		wantErr bool
	}{
		{
			name:    "ShouldPassFutureExpiration",
			claims:  &LogoutTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))},
			wantErr: false,
		},
		{
			name:    "ShouldFailPastExpiration",
			claims:  &LogoutTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))},
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

func TestLogoutTokenClaims_ToMapClaimsSetsID(t *testing.T) {
	assert.NotEmpty(t, (new(LogoutTokenClaims)).ToMapClaims()[ClaimJWTID])
}

func TestLogoutTokenClaims_ToMap(t *testing.T) {
	base := &LogoutTokenClaims{
		JTI:            "foo-id",
		Subject:        "peter",
		IssuedAt:       Now(),
		Issuer:         "authelia",
		Audience:       []string{"tests"},
		ExpirationTime: NewNumericDate(time.Now().Add(time.Hour)),
		SessionID:      "abc123",
		Extra: map[string]any{
			"foo": "bar",
			"baz": "bar",
		},
	}

	testCases := []struct {
		name      string
		sessionID string
	}{
		{
			name:      "ShouldEncodeOriginalSessionID",
			sessionID: "abc123",
		},
		{
			name:      "ShouldEncodeUpdatedSessionID",
			sessionID: "zyz123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := *base
			c.SessionID = tc.sessionID

			expected := map[string]any{
				consts.ClaimJWTID:          c.JTI,
				consts.ClaimSubject:        c.Subject,
				consts.ClaimIssuedAt:       c.IssuedAt.Unix(),
				consts.ClaimIssuer:         c.Issuer,
				consts.ClaimAudience:       c.Audience,
				consts.ClaimExpirationTime: c.ExpirationTime.Unix(),
				ClaimSessionID:             c.SessionID,
				ClaimEvents: map[string]any{
					ClaimEventBackChannelLogout: map[string]any{},
				},
				"foo": c.Extra["foo"],
				"baz": c.Extra["baz"],
			}

			assert.Equal(t, expected, c.ToMap())

			data, err := json.Marshal(c.ToMap())
			require.NoError(t, err)

			expectedJSON := fmt.Sprintf(
				`{"aud":["tests"],"baz":"bar","events":{"http://schemas.openid.net/event/backchannel-logout":{}},"exp":%d,"foo":"bar","iat":%d,"iss":"authelia","jti":"foo-id","sid":%q,"sub":"peter"}`,
				c.ExpirationTime.Unix(), c.IssuedAt.Unix(), c.SessionID,
			)
			assert.Equal(t, expectedJSON, string(data))
		})
	}
}

func TestNewLogoutTokenClaims(t *testing.T) {
	before := time.Now()
	extra := map[string]any{"foo": "bar"}

	claims := NewLogoutTokenClaims("peter", []string{"a", "b"}, "sid-1", extra)
	after := time.Now()

	require.NotNil(t, claims)
	assert.Equal(t, "peter", claims.Subject)
	assert.Equal(t, []string{"a", "b"}, claims.Audience)
	assert.Equal(t, "sid-1", claims.SessionID)
	assert.Equal(t, extra, claims.Extra)

	require.NotNil(t, claims.IssuedAt)
	assert.False(t, claims.IssuedAt.Before(before.Truncate(time.Second)))
	assert.False(t, claims.IssuedAt.After(after))

	assert.NotNil(t, claims.Events.BackChannelLogout)
	assert.Empty(t, claims.Events.BackChannelLogout)
}

func TestLogoutTokenClaims_Getters(t *testing.T) {
	exp := NewNumericDate(time.Now().Add(time.Hour))
	iat := NewNumericDate(time.Now())

	claims := &LogoutTokenClaims{
		Issuer:         "authelia",
		Subject:        "peter",
		Audience:       []string{"tests"},
		ExpirationTime: exp,
		IssuedAt:       iat,
	}

	actualExp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.Equal(t, exp, actualExp)

	actualIat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	assert.Equal(t, iat, actualIat)

	actualNbf, err := claims.GetNotBefore()
	require.NoError(t, err)
	assert.Nil(t, actualNbf, "Logout tokens never carry nbf")

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

func TestLogoutTokenClaims_SafeGetters(t *testing.T) {
	zero := time.Unix(0, 0).UTC()
	now := time.Now().UTC().Truncate(time.Second)

	testCases := []struct {
		name   string
		claims *LogoutTokenClaims
		expExp time.Time
		expIat time.Time
	}{
		{
			name:   "ShouldReturnZeroWhenUnset",
			claims: &LogoutTokenClaims{},
			expExp: zero,
			expIat: zero,
		},
		{
			name: "ShouldReturnValuesWhenSet",
			claims: &LogoutTokenClaims{
				ExpirationTime: NewNumericDate(now),
				IssuedAt:       NewNumericDate(now),
			},
			expExp: now,
			expIat: now,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expExp, tc.claims.GetExpirationTimeSafe())
			assert.Equal(t, tc.expIat, tc.claims.GetIssuedAtSafe())
		})
	}
}

func TestLogoutTokenClaims_Add(t *testing.T) {
	t.Run("ShouldInitializeExtraWhenNil", func(t *testing.T) {
		c := &LogoutTokenClaims{}
		c.Add("foo", "bar")
		assert.Equal(t, "bar", c.Extra["foo"])
	})

	t.Run("ShouldAddToExistingExtra", func(t *testing.T) {
		c := &LogoutTokenClaims{Extra: map[string]any{"existing": 1}}
		c.Add("foo", "bar")
		assert.Equal(t, 1, c.Extra["existing"])
		assert.Equal(t, "bar", c.Extra["foo"])
	})
}

func TestLogoutTokenClaims_Get(t *testing.T) {
	c := &LogoutTokenClaims{
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

func TestLogoutTokenClaims_Valid(t *testing.T) {
	fixedTime := time.Unix(1700000000, 0).UTC()
	future := NewNumericDate(fixedTime.Add(time.Hour))
	past := NewNumericDate(fixedTime.Add(-time.Hour))
	timeFunc := func() time.Time { return fixedTime }

	testCases := []struct {
		name string
		have *LogoutTokenClaims
		opts []ClaimValidationOption
		errs uint32
		err  string
	}{
		{
			name: "ShouldPassEmpty",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
		},
		{
			name: "ShouldFailExpiredEXP",
			have: &LogoutTokenClaims{ExpirationTime: past},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
			errs: ValidationErrorExpired,
			err:  "Token is expired",
		},
		{
			name: "ShouldFailIATInFuture",
			have: &LogoutTokenClaims{IssuedAt: future},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc)},
			errs: ValidationErrorIssuedAt,
			err:  "Token used before issued",
		},
		{
			name: "ShouldFailRequireEXP",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateRequireExpiresAt()},
			errs: ValidationErrorExpired,
			err:  "Token is expired",
		},
		{
			name: "ShouldFailRequireIAT",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateRequireIssuedAt()},
			errs: ValidationErrorIssuedAt,
			err:  "Token used before issued",
		},
		{
			name: "ShouldPassIssuer",
			have: &LogoutTokenClaims{Issuer: "authelia"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
		},
		{
			name: "ShouldFailIssuerMismatch",
			have: &LogoutTokenClaims{Issuer: "wrong"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
			errs: ValidationErrorIssuer,
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldFailIssuerAbsentRequired",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia")},
			errs: ValidationErrorIssuer,
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldPassIssuerAbsentNotRequired",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateIssuer("authelia"), ValidateDoNotRequireIssuer()},
		},
		{
			name: "ShouldPassSubject",
			have: &LogoutTokenClaims{Subject: "peter"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
		},
		{
			name: "ShouldFailSubjectMismatch",
			have: &LogoutTokenClaims{Subject: "wrong"},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
			errs: ValidationErrorSubject,
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldFailSubjectAbsent",
			have: &LogoutTokenClaims{},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateSubject("peter")},
			errs: ValidationErrorSubject,
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldPassAudienceAny",
			have: &LogoutTokenClaims{Audience: []string{"a", "b"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAny("b")},
		},
		{
			name: "ShouldFailAudienceAnyNoMatch",
			have: &LogoutTokenClaims{Audience: []string{"x"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAny("a")},
			errs: ValidationErrorAudience,
			err:  "Token has invalid audience",
		},
		{
			name: "ShouldPassAudienceAll",
			have: &LogoutTokenClaims{Audience: []string{"a", "b"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAll("a", "b")},
		},
		{
			name: "ShouldFailAudienceAllMissing",
			have: &LogoutTokenClaims{Audience: []string{"a"}},
			opts: []ClaimValidationOption{ValidateTimeFunc(timeFunc), ValidateAudienceAll("a", "b")},
			errs: ValidationErrorAudience,
			err:  "Token has invalid audience",
		},
		{
			name: "ShouldUseDefaultTimeFuncWhenNone",
			have: &LogoutTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))},
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

func TestLogoutTokenClaims_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name    string
		raw     string
		expect  func(t *testing.T, c *LogoutTokenClaims)
		wantErr string
	}{
		{
			name: "ShouldDecodeAllStandardClaims",
			raw: `{
				"jti":"id-1",
				"iss":"authelia",
				"sub":"peter",
				"sid":"sess-1",
				"aud":["tests"],
				"exp":1700003600,
				"iat":1700000000
			}`,
			expect: func(t *testing.T, c *LogoutTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, "authelia", c.Issuer)
				assert.Equal(t, "peter", c.Subject)
				assert.Equal(t, "sess-1", c.SessionID)
				assert.Equal(t, []string{"tests"}, c.Audience)
				assert.Equal(t, int64(1700003600), c.ExpirationTime.Unix())
				assert.Equal(t, int64(1700000000), c.IssuedAt.Unix())
			},
		},
		{
			name: "ShouldRouteUnknownClaimsToExtra",
			raw:  `{"jti":"id-1","custom":"value"}`,
			expect: func(t *testing.T, c *LogoutTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, "value", c.Extra["custom"])
			},
		},
		{
			name: "ShouldDecodeExtraClaim",
			raw:  `{"jti":"id-1","ext":{"foo":"bar"}}`,
			expect: func(t *testing.T, c *LogoutTokenClaims) {
				assert.Equal(t, "id-1", c.JTI)
				assert.Equal(t, map[string]any{"foo": "bar"}, c.Extra)
			},
		},
		{
			name:    "ShouldRejectNonceClaim",
			raw:     `{"nonce":"abc"}`,
			wantErr: "nonce is not a valid logout token claim",
		},
		{
			name:    "ShouldErrorOnUndecodableJTI",
			raw:     `{"jti":123}`,
			wantErr: "claim jti with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableSubject",
			raw:     `{"sub":123}`,
			wantErr: "claim sub with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableIssuer",
			raw:     `{"iss":123}`,
			wantErr: "claim iss with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableSessionID",
			raw:     `{"sid":123}`,
			wantErr: "claim sid with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableAudience",
			raw:     `{"aud":123}`,
			wantErr: "claim aud with value 123 could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableExp",
			raw:     `{"exp":"not-a-time"}`,
			wantErr: "claim exp with value not-a-time could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableIAT",
			raw:     `{"iat":"not-a-time"}`,
			wantErr: "claim iat with value not-a-time could not be decoded",
		},
		{
			name:    "ShouldErrorOnUndecodableExtra",
			raw:     `{"ext":"not-a-map"}`,
			wantErr: "claim ext with value not-a-map could not be decoded",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c LogoutTokenClaims

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
		var c LogoutTokenClaims

		require.Error(t, c.UnmarshalJSON([]byte(`not-json`)))
	})
}
