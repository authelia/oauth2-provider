// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientIDMetadataDocumentClientRebuiltByTheStore(t *testing.T) {
	t.Run("ShouldRefreshAndIntrospectWithAFreshRecord", func(t *testing.T) {
		env, store, id, token := newCIMDRehydrationEnv(t)

		refreshed := env.token(t, http.StatusOK, url.Values{
			consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: {token["refresh_token"].(string)},
			consts.FormParameterClientID:     {id},
		})

		require.NotEmpty(t, refreshed["access_token"])

		status, introspected := env.introspect(t, refreshed["access_token"].(string))

		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, introspected["active"])
		assert.Equal(t, id, introspected["client_id"])

		assert.Equal(t, int64(1), env.documentHits("/public.json"))
		assert.Positive(t, store.rebuilt.Load())
	})

	t.Run("ShouldRefetchOnceAndRefreshWithAnExpiredRecord", func(t *testing.T) {
		env, store, id, token := newCIMDRehydrationEnv(t)

		store.expireDocument(t, id)

		refreshed := env.token(t, http.StatusOK, url.Values{
			consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: {token["refresh_token"].(string)},
			consts.FormParameterClientID:     {id},
		})

		require.NotEmpty(t, refreshed["access_token"])

		status, introspected := env.introspect(t, refreshed["access_token"].(string))

		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, introspected["active"])

		assert.Equal(t, int64(2), env.documentHits("/public.json"))
	})

	t.Run("ShouldRefuseRefreshAndNotReportActiveWithAnExpiredRecordAndNoDocument", func(t *testing.T) {
		env, store, id, token := newCIMDRehydrationEnv(t)

		status, introspected := env.introspect(t, token["access_token"].(string))

		require.Equal(t, http.StatusOK, status)
		require.Equal(t, true, introspected["active"])

		store.expireDocument(t, id)
		env.removeDocument("/public.json")

		status, refused := env.form(t, tokenRelativePath, url.Values{
			consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: {token["refresh_token"].(string)},
			consts.FormParameterClientID:     {id},
		}, false)

		assert.GreaterOrEqual(t, status, http.StatusBadRequest)
		assert.Equal(t, "invalid_client", refused["error"])
		assert.Empty(t, refused["access_token"])

		status, introspected = env.introspect(t, token["access_token"].(string))

		t.Logf("introspection of an access token whose client can no longer be rebuilt: %d %v", status, introspected)

		assert.NotEqual(t, true, introspected["active"])

		_, err := store.GetClientIDMetadataDocument(t.Context(), id)

		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})
}

type rehydratingStore struct {
	*storage.MemoryStore

	config  *oauth2.Config
	rebuilt atomic.Int64
}

func (s *rehydratingStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetAccessTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	return s.rebuild(ctx, request)
}

func (s *rehydratingStore) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetRefreshTokenSession(ctx, signature, session); err != nil && !errors.Is(err, oauth2.ErrInactiveToken) {
		return nil, err
	}

	if stored, ok := request.(storage.StoreRefreshToken); ok {
		request = stored.Requester
	}

	rebuilt, rerr := s.rebuild(ctx, request)
	if rerr != nil {
		return nil, rerr
	}

	return rebuilt, err
}

func (s *rehydratingStore) rebuild(ctx context.Context, request oauth2.Requester) (rebuilt oauth2.Requester, err error) {
	var client oauth2.Client

	if client, err = oauth2.GetClient(ctx, s.config, s.MemoryStore, request.GetClient().GetID()); err != nil {
		return nil, err
	}

	s.rebuilt.Add(1)

	switch req := request.(type) {
	case *oauth2.AccessRequest:
		clone := *req
		clone.Client = client

		return &clone, nil
	case *oauth2.Request:
		clone := *req
		clone.Client = client

		return &clone, nil
	default:
		return nil, fmt.Errorf("the rehydrating store can not clone a %T", request)
	}
}

func (s *rehydratingStore) expireDocument(t *testing.T, id string) {
	t.Helper()

	record, err := s.GetClientIDMetadataDocument(t.Context(), id)
	require.NoError(t, err)

	record.ExpiresAt = time.Now().Add(-time.Minute)

	require.NoError(t, s.SetClientIDMetadataDocument(t.Context(), record))
}

func newCIMDRehydrationEnv(t *testing.T) (env *cimdEnv, store *rehydratingStore, id string, token map[string]any) {
	t.Helper()

	store = &rehydratingStore{MemoryStore: storage.NewMemoryStore()}

	store.Clients["introspector"] = &oauth2.DefaultClient{
		ID:           "introspector",
		ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
	}

	env = newCIMDEnv(t, store, true, true, func(_ *cimdEnv, config *oauth2.Config) {
		store.config = config
	})

	id = env.documents.URL + "/public.json"

	env.setDocument("/public.json", map[string]any{
		"client_id":                  id,
		"client_name":                "Public Example",
		"application_type":           "native",
		"redirect_uris":              []string{env.provider.URL + "/callback"},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      "oauth2 offline",
	})

	const verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"

	response, err := http.Get(env.provider.URL + "/auth?" + url.Values{ //nolint:gosec
		consts.FormParameterClientID:      {id},
		consts.FormParameterResponseType:  {"code"},
		consts.FormParameterRedirectURI:   {env.provider.URL + "/callback"},
		consts.FormParameterScope:         {"oauth2 offline"},
		consts.FormParameterState:         {testState},
		consts.FormParameterCodeChallenge: {verifier},
	}.Encode())
	require.NoError(t, err)

	defer response.Body.Close()

	require.Equal(t, http.StatusOK, response.StatusCode)

	code := response.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
	require.NotEmpty(t, code)

	token = env.token(t, http.StatusOK, url.Values{
		consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: {code},
		consts.FormParameterClientID:          {id},
		consts.FormParameterRedirectURI:       {env.provider.URL + "/callback"},
		consts.FormParameterCodeVerifier:      {verifier},
	})

	require.NotEmpty(t, token["access_token"])
	require.NotEmpty(t, token["refresh_token"])
	require.Equal(t, int64(1), env.documentHits("/public.json"))

	return env, store, id, token
}

func (e *cimdEnv) removeDocument(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.docs, path)
}

func (e *cimdEnv) introspect(t *testing.T, token string) (status int, body map[string]any) {
	t.Helper()

	return e.form(t, "/introspect", url.Values{consts.FormParameterToken: {token}}, true)
}

func (e *cimdEnv) form(t *testing.T, path string, form url.Values, authenticate bool) (status int, body map[string]any) {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, e.provider.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	request.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

	if authenticate {
		request.SetBasicAuth("introspector", testClientSecret)
	}

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)

	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	body = map[string]any{}

	require.NoError(t, json.Unmarshal(data, &body), "Got body: %s", string(data))

	return response.StatusCode, body
}
