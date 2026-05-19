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

func TestLogoutTokenClaims_Valid(t *testing.T) {
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
