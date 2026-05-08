// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestWriteIntrospectionError(t *testing.T) {
	provider := &Fosite{Config: new(Config)}
	c := gomock.NewController(t)
	defer c.Finish()

	rw := mock.NewMockResponseWriter(c)
	rw.EXPECT().WriteHeader(http.StatusUnauthorized)
	rw.EXPECT().Header().AnyTimes().Return(http.Header{})
	rw.EXPECT().Write(gomock.Any())
	provider.WriteIntrospectionError(context.Background(), rw, errorsx.WithStack(ErrRequestUnauthorized))

	rw.EXPECT().WriteHeader(http.StatusBadRequest)
	rw.EXPECT().Write(gomock.Any())
	provider.WriteIntrospectionError(context.Background(), rw, errorsx.WithStack(ErrInvalidRequest))

	rw.EXPECT().Write([]byte("{\"active\":false}\n"))
	provider.WriteIntrospectionError(context.Background(), rw, errors.New(""))

	rw.EXPECT().Write([]byte("{\"active\":false}\n"))
	provider.WriteIntrospectionError(context.Background(), rw, errorsx.WithStack(ErrInactiveToken.WithWrap(ErrRequestUnauthorized)))

	provider.WriteIntrospectionError(context.Background(), rw, nil)
}

func TestWriteIntrospectionResponse(t *testing.T) {
	provider := new(Fosite)
	c := gomock.NewController(t)
	defer c.Finish()

	rw := mock.NewMockResponseWriter(c)
	rw.EXPECT().Write(gomock.Any()).AnyTimes()
	rw.EXPECT().Header().AnyTimes().Return(http.Header{})
	rw.EXPECT().WriteHeader(200)
	provider.WriteIntrospectionResponse(context.Background(), rw, &IntrospectionResponse{
		AccessRequester: NewAccessRequest(nil),
	})
}

func TestWriteIntrospectionResponseBody(t *testing.T) {
	provider := new(Fosite)
	ires := &IntrospectionResponse{}
	rw := httptest.NewRecorder()

	for _, c := range []struct {
		description string
		setup       func()
		active      bool
		hasExp      bool
		hasExtra    bool
	}{
		{
			description: "should success for not expired access token",
			setup: func() {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExp:   true,
			hasExtra: false,
		},
		{
			description: "should success for expired access token",
			setup: func() {
				ires.Active = false
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(-time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   false,
			hasExp:   false,
			hasExtra: false,
		},
		{
			description: "should success for ExpirationTime not set access token",
			setup: func() {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Time{})
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExp:   false,
			hasExtra: false,
		},
		{
			description: "should output extra claims",
			setup: func() {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.GetExtraClaims()["extra"] = "foobar"
				// We try to set these, but they should be ignored.
				for _, field := range []string{consts.ClaimExpirationTime, consts.ClaimClientIdentifier, consts.ClaimScope, consts.ClaimIssuedAt, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimUsername} {
					session.GetExtraClaims()[field] = "invalid"
				}
				session.SetExpiresAt(ires.TokenUse, time.Time{})
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExp:   false,
			hasExtra: true,
		},
		{
			description: "should success for not expired refresh token",
			setup: func() {
				ires.Active = true
				ires.TokenUse = RefreshToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExp:   true,
			hasExtra: false,
		},
		{
			description: "should not leak access token exp when introspecting refresh token",
			setup: func() {
				ires.Active = true
				ires.TokenUse = RefreshToken
				session := &DefaultSession{}
				// Only the access token expiry is set, the refresh token has none.
				// The introspection response must reflect the refresh token, not leak the access token expiry.
				session.SetExpiresAt(AccessToken, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExp:   false,
			hasExtra: false,
		},
	} {
		t.Run(c.description, func(t *testing.T) {
			c.setup()
			provider.WriteIntrospectionResponse(context.Background(), rw, ires)
			var params struct {
				Active   bool   `json:"active"`
				Exp      *int64 `json:"exp"`
				Iat      *int64 `json:"iat"`
				Extra    string `json:"extra"`
				ClientId string `json:"client_id"`
				Scope    string `json:"scope"`
				Subject  string `json:"sub"`
				Audience string `json:"aud"`
				Username string `json:"username"`
			}
			assert.Equal(t, 200, rw.Code)
			err := json.NewDecoder(rw.Body).Decode(&params)
			require.NoError(t, err)
			assert.Equal(t, c.active, params.Active)
			if c.active {
				assert.NotNil(t, params.Iat)
				if c.hasExp {
					assert.NotNil(t, params.Exp)
				} else {
					assert.Nil(t, params.Exp)
				}
				if c.hasExtra {
					assert.Equal(t, params.Extra, "foobar")
				} else {
					assert.Empty(t, params.Extra)
				}
				assert.NotEqual(t, "invalid", params.Exp)
				assert.NotEqual(t, "invalid", params.ClientId)
				assert.NotEqual(t, "invalid", params.Scope)
				assert.NotEqual(t, "invalid", params.Iat)
				assert.NotEqual(t, "invalid", params.Subject)
				assert.NotEqual(t, "invalid", params.Audience)
				assert.NotEqual(t, "invalid", params.Username)
			}
		})
	}
}

func TestWriteIntrospectionResponseBodyExpiryMatchesTokenUse(t *testing.T) {
	provider := new(Fosite)

	accessExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	refreshExpiry := time.Now().Add(time.Hour * 24).Truncate(time.Second)

	for _, c := range []struct {
		description string
		tokenUse    TokenUse
		expected    int64
	}{
		{
			description: "access token introspection returns access token expiry",
			tokenUse:    AccessToken,
			expected:    accessExpiry.Unix(),
		},
		{
			description: "refresh token introspection returns refresh token expiry",
			tokenUse:    RefreshToken,
			expected:    refreshExpiry.Unix(),
		},
	} {
		t.Run(c.description, func(t *testing.T) {
			session := &DefaultSession{}
			session.SetExpiresAt(AccessToken, accessExpiry)
			session.SetExpiresAt(RefreshToken, refreshExpiry)

			ires := &IntrospectionResponse{
				Active:          true,
				TokenUse:        c.tokenUse,
				AccessRequester: NewAccessRequest(session),
			}

			rw := httptest.NewRecorder()
			provider.WriteIntrospectionResponse(context.Background(), rw, ires)

			var params struct {
				Exp *int64 `json:"exp"`
			}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))
			require.NotNil(t, params.Exp)
			assert.Equal(t, c.expected, *params.Exp)
		})
	}
}
