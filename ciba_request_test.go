// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestBackChannelAuthenticationRequestSanitize(t *testing.T) {
	r := NewBackChannelAuthenticationRequest()
	r.Form = url.Values{
		"client_notification_token": {"secret"},
		"user_code":                 {"1234"},
		"binding_message":           {"hi"},
		"login_hint":                {"john"},
	}
	r.ClientNotificationToken = "secret"
	r.AuthRequestID = "id"
	r.UserCode = "1234"
	r.Status = CIBAStatusApproved

	actual, ok := r.Sanitize([]string{"client_notification_token", "user_code", "binding_message"}).(*BackChannelAuthenticationRequest)
	require.True(t, ok)

	assert.Empty(t, actual.Form.Get("client_notification_token"))
	assert.Empty(t, actual.Form.Get("user_code"))
	assert.Equal(t, "hi", actual.Form.Get("binding_message"))
	assert.Empty(t, actual.Form.Get("login_hint"))
	assert.Equal(t, CIBAStatusApproved, actual.Status)
	assert.Empty(t, actual.AuthRequestID)
	assert.Empty(t, actual.ClientNotificationToken)
	assert.Equal(t, "id", r.AuthRequestID)
	assert.Equal(t, "secret", r.ClientNotificationToken)

	assert.Equal(t, "secret", r.Form.Get("client_notification_token"))
}

func TestBackChannelAuthenticationRequestMerge(t *testing.T) {
	now := time.Now().UTC()

	src := NewBackChannelAuthenticationRequest()
	src.SetID("abc")
	src.SetStatus(CIBAStatusDenied)
	src.SetAuthRequestIDSignature("sig")
	src.SetLastPolled(now)
	src.SetPollingInterval(7 * time.Second)
	src.SetSlowDownCount(3)
	src.SetFailureCause("cause")
	src.ClientNotificationToken = "tok"
	src.AuthRequestID = "id"
	src.DeliveryMode = "ping"
	src.HintKind = CIBAHintKindLoginHint
	src.HintValue = "john"
	src.IDTokenHintClaims = jwt.MapClaims{"sub": "x"}
	src.BindingMessage = "bm"
	src.UserCode = "uc"
	src.RequestedExpiry = time.Minute
	src.RequestContext = json.RawMessage(`{"a":1}`)

	dst := NewBackChannelAuthenticationRequest()
	dst.Merge(src)

	assert.Equal(t, "abc", dst.GetID())
	assert.Equal(t, CIBAStatusDenied, dst.GetStatus())
	assert.Equal(t, "sig", dst.GetAuthRequestIDSignature())
	assert.True(t, now.Equal(dst.GetLastPolled()))
	assert.Equal(t, 7*time.Second, dst.GetPollingInterval())
	assert.Equal(t, 3, dst.GetSlowDownCount())
	assert.Equal(t, "cause", dst.GetFailureCause())
	assert.Equal(t, "tok", GetClientNotificationToken(dst))
	assert.Equal(t, "id", GetAuthRequestID(dst))
	assert.Equal(t, "ping", dst.GetDeliveryMode())

	kind, value := dst.GetHint()
	assert.Equal(t, CIBAHintKindLoginHint, kind)
	assert.Equal(t, "john", value)
	assert.Equal(t, "x", dst.GetIDTokenHintClaims()["sub"])
	assert.Equal(t, "bm", dst.GetBindingMessage())
	assert.Equal(t, "uc", dst.GetUserCode())
	assert.Equal(t, time.Minute, dst.GetRequestedExpiry())
	assert.JSONEq(t, `{"a":1}`, string(dst.GetRequestContext()))

	assert.Empty(t, GetClientNotificationToken(&nilCIBARequester{}))
}

// nilCIBARequester is a requester which is not a *BackChannelAuthenticationRequest.
type nilCIBARequester struct {
	BackChannelAuthenticationRequester
}
