// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
)

func newCIBATokenHandlerWithSession(t *testing.T, status oauth2.CIBAStatus, lastChecked time.Time, expiresAt time.Time) (*CIBATokenHandler, *memoryCIBAStorage) {
	t.Helper()

	store := newMemoryCIBAStorage()
	handler := &CIBATokenHandler{
		Storage:  store,
		Strategy: &fakeAuthRequestIDStrategy{id: "id-1", signature: "sig-1"},
		Config: &oauth2.Config{
			OpenIDCIBAPollingInterval: time.Second * 5,
		},
	}

	session := openid.NewDefaultSession()
	if !expiresAt.IsZero() {
		session.SetExpiresAt(oauth2.CIBAAuthRequestID, expiresAt)
	}

	saved := oauth2.NewCIBARequest()
	saved.SetSession(session)
	saved.Client = &oauth2.DefaultClient{ID: "client-1"}
	saved.SetID("ciba-req-1")
	saved.SetAuthRequestIDSignature("sig-1")
	saved.SetStatus(status)
	saved.SetLastChecked(lastChecked)

	require.NoError(t, store.CreateOpenIDCIBASession(t.Context(), "sig-1", saved))

	return handler, store
}

func newAccessRequest(t *testing.T, code string) *oauth2.AccessRequest {
	t.Helper()

	r := oauth2.NewAccessRequest(openid.NewDefaultSession())
	r.Client = &oauth2.DefaultClient{ID: "client-1", GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)}}
	r.GrantTypes = oauth2.Arguments{string(oauth2.GrantTypeOpenIDCIBA)}
	r.Form.Set(consts.FormParameterAuthReqID, code)
	r.SetRequestedAt(time.Now())

	return r
}

func TestCIBATokenHandler_CanHandleTokenEndpointRequest(t *testing.T) {
	h := &CIBATokenHandler{}

	wrong := oauth2.NewAccessRequest(openid.NewDefaultSession())
	wrong.GrantTypes = oauth2.Arguments{string(oauth2.GrantTypeAuthorizationCode)}

	assert.False(t, h.CanHandleTokenEndpointRequest(context.Background(), wrong))

	right := oauth2.NewAccessRequest(openid.NewDefaultSession())
	right.GrantTypes = oauth2.Arguments{string(oauth2.GrantTypeOpenIDCIBA)}

	assert.True(t, h.CanHandleTokenEndpointRequest(context.Background(), right))
}

func TestCIBATokenHandler_CanSkipClientAuth(t *testing.T) {
	h := &CIBATokenHandler{}

	assert.False(t, h.CanSkipClientAuth(context.Background(), oauth2.NewAccessRequest(openid.NewDefaultSession())))
}

func TestCIBATokenHandler_ValidateGrantTypes(t *testing.T) {
	h := &CIBATokenHandler{}

	without := oauth2.NewAccessRequest(openid.NewDefaultSession())
	without.Client = &oauth2.DefaultClient{ID: "no-grant", GrantTypes: []string{}}

	err := h.ValidateGrantTypes(context.Background(), without)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)

	with := oauth2.NewAccessRequest(openid.NewDefaultSession())
	with.Client = &oauth2.DefaultClient{ID: "client", GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)}}
	assert.NoError(t, h.ValidateGrantTypes(context.Background(), with))
}

func TestCIBATokenHandler_GetCodeAndSession_MissingAuthReqID(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusNew, time.Time{}, time.Time{})

	request := newAccessRequest(t, "")

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestCIBATokenHandler_GetCodeAndSession_AuthorizationPending(t *testing.T) {
	handler, store := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusNew, time.Time{}, time.Time{})

	request := newAccessRequest(t, "id-1")

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrAuthorizationPending)

	// The polling timestamp should have been updated for the next slow_down check.
	persisted, gErr := store.GetOpenIDCIBASession(t.Context(), "sig-1", request.GetSession())
	require.NoError(t, gErr)
	assert.False(t, persisted.GetLastChecked().IsZero())
}

func TestCIBATokenHandler_GetCodeAndSession_AccessDenied(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusDenied, time.Time{}, time.Time{})

	request := newAccessRequest(t, "id-1")

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
}

func TestCIBATokenHandler_GetCodeAndSession_SlowDown(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusNew, time.Now(), time.Time{})

	request := newAccessRequest(t, "id-1")

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrSlowDown)
}

func TestCIBATokenHandler_GetCodeAndSession_Expired(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusNew, time.Time{}, time.Now().Add(-time.Minute))

	request := newAccessRequest(t, "id-1")

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
}

func TestCIBATokenHandler_GetCodeAndSession_ClientMismatch(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusApproved, time.Time{}, time.Time{})

	request := newAccessRequest(t, "id-1")
	request.Client = &oauth2.DefaultClient{ID: "wrong-client", GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)}}

	_, _, _, err := handler.GetCodeAndSession(t.Context(), request)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

func TestCIBATokenHandler_GetCodeAndSession_Approved(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusApproved, time.Time{}, time.Time{})

	request := newAccessRequest(t, "id-1")

	code, signature, session, err := handler.GetCodeAndSession(t.Context(), request)
	require.NoError(t, err)
	assert.Equal(t, "id-1", code)
	assert.Equal(t, "sig-1", signature)
	require.NotNil(t, session)
	assert.Equal(t, oauth2.CIBAStatusApproved, session.(oauth2.CIBARequester).GetStatus())
}

func TestCIBATokenHandler_InvalidateSession(t *testing.T) {
	handler, store := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusApproved, time.Time{}, time.Time{})

	require.NoError(t, handler.InvalidateSession(t.Context(), "sig-1", nil))

	_, err := store.GetOpenIDCIBASession(t.Context(), "sig-1", openid.NewDefaultSession())
	assert.Error(t, err)
}

func TestCIBATokenHandler_DeviceCodeSignature(t *testing.T) {
	handler, _ := newCIBATokenHandlerWithSession(t, oauth2.CIBAStatusNew, time.Time{}, time.Time{})

	sig, err := handler.DeviceCodeSignature(t.Context(), "id-1")
	require.NoError(t, err)
	assert.Equal(t, "sig-1", sig)
}
