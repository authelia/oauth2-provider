// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

//nolint:unparam
func tokenRevocationHandler(t *testing.T, oauth2 oauth2.Provider, session oauth2.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.Background()
		err := oauth2.NewRevocationRequest(ctx, req)
		if err != nil {
			t.Logf("Revoke request failed because %+v", err)
		}
		oauth2.WriteRevocationResponse(req.Context(), rw, err)
	}
}

func tokenIntrospectionHandler(t *testing.T, oauth2 oauth2.Provider, session oauth2.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.Background()
		ar, err := oauth2.NewIntrospectionRequest(ctx, req, session)
		if err != nil {
			t.Logf("Introspection request failed because: %+v", err)
			oauth2.WriteIntrospectionError(req.Context(), rw, err)
			return
		}

		oauth2.WriteIntrospectionResponse(req.Context(), rw, ar)
	}
}

func tokenInfoHandler(t *testing.T, provider oauth2.Provider, session oauth2.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.Background()
		_, resp, err := provider.IntrospectToken(ctx, oauth2.AccessTokenFromRequest(req), oauth2.AccessToken, session)
		if err != nil {
			t.Logf("Info request failed because: %+v", err)
			var e *oauth2.RFC6749Error
			require.True(t, errors.As(err, &e))
			http.Error(rw, e.DescriptionField, e.CodeField)
			return
		}

		t.Logf("Introspecting caused: %+v", resp)

		if err := json.NewEncoder(rw).Encode(resp); err != nil {
			panic(err)
		}
	}
}

func authEndpointHandler(t *testing.T, provider oauth2.Provider, session oauth2.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewAuthorizeRequest(ctx, req)
		if err != nil {
			t.Logf("Access request failed because: %+v", err)
			t.Logf("Request: %+v", ar)
			provider.WriteAuthorizeError(req.Context(), rw, ar, err)
			return
		}

		if ar.GetRequestedScopes().Has("oauth2") {
			ar.GrantScope("oauth2")
		}

		if ar.GetRequestedScopes().Has(consts.ScopeOffline) {
			ar.GrantScope(consts.ScopeOffline)
		}

		if ar.GetRequestedScopes().Has(consts.ScopeOpenID) {
			ar.GrantScope(consts.ScopeOpenID)
		}

		for _, a := range ar.GetRequestedAudience() {
			ar.GrantAudience(a)
		}

		// Normally, this would be the place where you would check if the user is logged in and gives his consent.
		// For this test, let's assume that the user exists, is logged in, and gives his consent...

		response, err := provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			t.Logf("Access request failed because: %+v", err)
			t.Logf("Request: %+v", ar)
			provider.WriteAuthorizeError(req.Context(), rw, ar, err)
			return
		}

		provider.WriteAuthorizeResponse(req.Context(), rw, ar, response)
	}
}

func authCallbackHandler(t *testing.T) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		if q.Get("code") == "" && q.Get("error") == "" {
			assert.NotEmpty(t, q.Get("code"))
			assert.NotEmpty(t, q.Get("error"))
		}

		if q.Get("code") != "" {
			_, _ = rw.Write([]byte("code: ok"))
		}
		if q.Get("error") != "" {
			rw.WriteHeader(http.StatusNotAcceptable)
			_, _ = rw.Write([]byte("error: " + q.Get("error")))
		}
	}
}

//nolint:unparam
func tokenEndpointHandler(t *testing.T, provider oauth2.Provider) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		_ = req.ParseMultipartForm(1 << 20)

		ctx := oauth2.NewContext()

		requester, err := provider.NewAccessRequest(ctx, req, &hoauth2.JWTSession{})
		if err != nil {
			provider.WriteAccessError(req.Context(), rw, requester, err)
			return
		}

		if requester.GetRequestedScopes().Has("oauth2") {
			requester.GrantScope("oauth2")
		}

		response, err := provider.NewAccessResponse(ctx, requester)
		if err != nil {
			provider.WriteAccessError(req.Context(), rw, requester, err)
			return
		}

		provider.WriteAccessResponse(req.Context(), rw, requester, response)
	}
}

//nolint:unparam
func pushedAuthorizeRequestHandler(t *testing.T, provider oauth2.Provider, session oauth2.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewPushedAuthorizeRequest(ctx, req)
		if err != nil {
			provider.WritePushedAuthorizeError(ctx, rw, ar, err)
			return
		}

		response, err := provider.NewPushedAuthorizeResponse(ctx, ar, session)
		if err != nil {
			provider.WritePushedAuthorizeError(ctx, rw, ar, err)
			return
		}

		provider.WritePushedAuthorizeResponse(ctx, rw, ar, response)
	}
}
