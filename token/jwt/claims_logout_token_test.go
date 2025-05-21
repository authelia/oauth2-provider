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

func TestLogoutTokenAssert(t *testing.T) {
	assert.NoError(t, (&LogoutTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))}).
		ToMapClaims().Valid())
	assert.Error(t, (&LogoutTokenClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))}).
		ToMapClaims().Valid())

	assert.NotEmpty(t, (new(LogoutTokenClaims)).ToMapClaims()[ClaimJWTID])
}

func TestLogoutTokenClaimsToMap(t *testing.T) {
	claims := &LogoutTokenClaims{
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

	assert.Equal(t, map[string]any{
		ClaimJWTID:          claims.JTI,
		ClaimSubject:        claims.Subject,
		ClaimIssuedAt:       claims.IssuedAt.Unix(),
		ClaimIssuer:         claims.Issuer,
		ClaimAudience:       claims.Audience,
		ClaimExpirationTime: claims.ExpirationTime.Unix(),
		ClaimSessionID:      claims.SessionID,
		ClaimEvents: map[string]any{
			ClaimEventBackChannelLogout: map[string]any{},
		},
		"foo": claims.Extra["foo"],
		"baz": claims.Extra["baz"],
	}, claims.ToMap())

	data, err := json.Marshal(claims.ToMap())
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf(`{"aud":["tests"],"baz":"bar","events":{"http://schemas.openid.net/event/backchannel-logout":{}},"exp":%d,"foo":"bar","iat":%d,"iss":"authelia","jti":"foo-id","sid":"abc123","sub":"peter"}`, claims.ExpirationTime.Unix(), claims.IssuedAt.Unix()), string(data))

	claims.SessionID = "zyz123"

	assert.Equal(t, map[string]any{
		consts.ClaimJWTID:          claims.JTI,
		consts.ClaimSubject:        claims.Subject,
		consts.ClaimIssuedAt:       claims.IssuedAt.Unix(),
		consts.ClaimIssuer:         claims.Issuer,
		consts.ClaimAudience:       claims.Audience,
		consts.ClaimExpirationTime: claims.ExpirationTime.Unix(),
		ClaimSessionID:             "zyz123",
		ClaimEvents: map[string]any{
			ClaimEventBackChannelLogout: map[string]any{},
		},
		"foo": claims.Extra["foo"],
		"baz": claims.Extra["baz"],
	}, claims.ToMap())

	data, err = json.Marshal(claims.ToMap())
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf(`{"aud":["tests"],"baz":"bar","events":{"http://schemas.openid.net/event/backchannel-logout":{}},"exp":%d,"foo":"bar","iat":%d,"iss":"authelia","jti":"foo-id","sid":"zyz123","sub":"peter"}`, claims.ExpirationTime.Unix(), claims.IssuedAt.Unix()), string(data))
}
