// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

// RFC 9700 Section 4.11.2.
func TestWriteAuthorizeErrorRedirectPolicy(t *testing.T) {
	static := &DefaultClient{ID: "static", RedirectURIs: []string{"https://client.example.com/cb"}}
	document := &redirectPolicyDocumentClient{DefaultClient: &DefaultClient{ID: "https://phish.example.com/client.json", RedirectURIs: []string{"https://phish.example.com/login"}}}

	testCases := []struct {
		name     string
		client   Client
		policy   AuthorizeErrorRedirectPolicy
		redirect bool
	}{
		{name: "ShouldRedirectForAStaticClient", client: static, redirect: true},
		{name: "ShouldNotRedirectForAClientIDMetadataDocumentClient", client: document},
		{name: "ShouldNotRedirectForAClientThePolicyDistrusts", client: static, policy: redirectPolicyFunc(func(AuthorizeRequester) bool { return false })},
		{name: "ShouldRedirectForAClientIDMetadataDocumentClientThePolicyTrusts", client: document, policy: redirectPolicyFunc(func(AuthorizeRequester) bool { return true }), redirect: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{AuthorizeErrorRedirectPolicy: tc.policy}}

			redirect, err := url.Parse(tc.client.GetRedirectURIs()[0])
			require.NoError(t, err)

			request := NewAuthorizeRequest()
			request.Client = tc.client
			request.RedirectURI = redirect
			request.ResponseMode = ResponseModeQuery
			request.State = "strong-enough-state"

			require.True(t, request.IsRedirectURIValid())

			recorder := httptest.NewRecorder()

			provider.WriteAuthorizeError(t.Context(), recorder, request, ErrInvalidScope)

			if tc.redirect {
				assert.Equal(t, http.StatusSeeOther, recorder.Code)
				assert.Contains(t, recorder.Header().Get(consts.HeaderLocation), redirect.String())

				return
			}

			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			assert.Empty(t, recorder.Header().Get(consts.HeaderLocation))
			assert.Equal(t, consts.ContentTypeApplicationJSON, recorder.Header().Get(consts.HeaderContentType))
			assert.Contains(t, recorder.Body.String(), "invalid_scope")
			assert.Equal(t, consts.CacheControlNoStore, recorder.Header().Get(consts.HeaderCacheControl))
		})
	}
}

func TestConfigGetAuthorizeErrorRedirectPolicyDefault(t *testing.T) {
	assert.Equal(t, DefaultAuthorizeErrorRedirectPolicy{}, (&Config{}).GetAuthorizeErrorRedirectPolicy(t.Context()))
}

type redirectPolicyDocumentClient struct {
	*DefaultClient
}

func (c *redirectPolicyDocumentClient) IsClientIDMetadataDocumentClient() bool { return true }

type redirectPolicyFunc func(request AuthorizeRequester) bool

func (f redirectPolicyFunc) TrustAuthorizeErrorRedirectURI(_ context.Context, request AuthorizeRequester, _ error) bool {
	return f(request)
}
