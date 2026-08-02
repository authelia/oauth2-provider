// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package rfc7591 (spec_test.go) is a spec compliance test suite for the RFC 7591 client registration endpoint, the
// RFC 7592 client configuration endpoint, and the OpenID Connect Dynamic Client Registration 1.0 metadata they both
// carry.
//
// These tests are written to map directly to numbered sections of those specs so that the behavior the
// implementation guarantees can be read out against the spec text. Each test name carries the relevant section
// reference and a description; failures should be interpreted as a divergence from that spec section.
//
// A number of cases in the task brief this file was written against turned out to already be covered verbatim by
// existing tests elsewhere in this package (or, for the two HTTP-transport-shaped cases, in the root package's
// request/response handler tests) - those are noted, not duplicated, in the task report rather than reproduced here.
//
// https://datatracker.ietf.org/doc/html/rfc7591
// https://datatracker.ietf.org/doc/html/rfc7592
// https://openid.net/specs/openid-connect-registration-1_0.html
package rfc7591

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

// §3.2.1: "client_id REQUIRED. Unique Client Identifier... client_id_issued_at OPTIONAL. Time at which the Client
// Identifier was issued. The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in
// UTC until the date/time of issuance."
func TestSpec_RFC7591_3_2_1_ResponseCarriesClientIDAndIssuedAt(t *testing.T) {
	ctx := context.Background()
	_, registrar, _, _ := newConfigurationHandler(t)

	before := time.Now().UTC().Unix()
	created := registerClient(t, ctx, registrar)
	after := time.Now().UTC().Unix()

	id, ok := created["client_id"].(string)
	require.True(t, ok, "RFC 7591 §3.2.1: 'client_id' is REQUIRED")
	assert.NotEmpty(t, id)

	issuedRaw, present := created["client_id_issued_at"]
	require.True(t, present, "RFC 7591 §3.2.1: 'client_id_issued_at' must be present when the server sets it")

	issued, ok := issuedRaw.(int64)
	require.True(t, ok, "'client_id_issued_at' must be a Unix timestamp (int64 seconds), got %T", issuedRaw)
	assert.GreaterOrEqual(t, issued, before, "'client_id_issued_at' must be the time of issuance")
	assert.LessOrEqual(t, issued, after, "'client_id_issued_at' must be the time of issuance")
}

// §3.2.1: "client_secret_expires_at REQUIRED if 'client_secret' is issued, OPTIONAL otherwise. Time at which the
// client_secret will expire or 0 if it will not expire."
func TestSpec_RFC7591_3_2_1_ClientSecretExpiresAtRequiredWithSecret(t *testing.T) {
	ctx := context.Background()

	t.Run("NeverExpiresByDefault", func(t *testing.T) {
		_, registrar, _, _ := newConfigurationHandler(t)

		created := registerClient(t, ctx, registrar)

		secret, ok := created["client_secret"].(string)
		require.True(t, ok, "a client secret must have been issued for this test to be meaningful")
		assert.NotEmpty(t, secret)

		expiresRaw, present := created["client_secret_expires_at"]
		require.True(t, present, "RFC 7591 §3.2.1: 'client_secret_expires_at' is REQUIRED when 'client_secret' is issued")
		assert.Equal(t, int64(0), expiresRaw, "0 means the secret will not expire")
	})

	t.Run("ReflectsConfiguredLifespan", func(t *testing.T) {
		_, registrar, config, _ := newConfigurationHandler(t)
		config.RFC7591ClientSecretLifespan = time.Hour

		before := time.Now().UTC().Add(time.Hour).Unix()
		created := registerClient(t, ctx, registrar)
		after := time.Now().UTC().Add(time.Hour).Unix()

		expiresRaw, present := created["client_secret_expires_at"]
		require.True(t, present)

		expires, ok := expiresRaw.(int64)
		require.True(t, ok, "'client_secret_expires_at' must be a Unix timestamp (int64 seconds), got %T", expiresRaw)
		assert.GreaterOrEqual(t, expires, before)
		assert.LessOrEqual(t, expires, after)
	})
}

// §3.2.2: "the authorization server responds with an HTTP 400 status code... 'error' [is] one of ...
// 'invalid_redirect_uri' ... 'invalid_client_metadata' ..."
func TestSpec_RFC7591_3_2_2_ErrorResponseShape(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidClientMetadata", func(t *testing.T) {
		_, registrar, config, _ := newConfigurationHandler(t)
		config.ScopeStrategy = oauth2.ExactScopeStrategy

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = &oauth2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/cb"},
			Scope:        "openid profile",
		}
		requester.Authenticated = grantableFixture(KindCreate, oauth2.Arguments{"openid"})

		err := registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
		require.Error(t, err)

		rfc := oauth2.ErrorToRFC6749Error(err)
		assert.Equal(t, http.StatusBadRequest, rfc.CodeField, "RFC 7591 §3.2.2: a rejected registration MUST be a 400")
		assert.Equal(t, "invalid_client_metadata", rfc.ErrorField)
	})

	t.Run("InvalidRedirectURI", func(t *testing.T) {
		_, registrar, config, _ := newConfigurationHandler(t)
		config.RFC7591ClientRegistrationValidators = []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = &oauth2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/cb#frag"},
		}

		err := registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
		require.Error(t, err)

		rfc := oauth2.ErrorToRFC6749Error(err)
		assert.Equal(t, http.StatusBadRequest, rfc.CodeField, "RFC 7591 §3.2.2: a rejected registration MUST be a 400")
		assert.Equal(t, "invalid_redirect_uri", rfc.ErrorField)
	})
}

// RFC 7591 §2: "scope ... OPTIONAL, [...] a space-separated list of scope values [...] that the client can use when
// requesting access tokens." An omitted 'scope' therefore registers a client with no scopes of its own, rather than
// silently inheriting some other set. This exercises the whole path (strategy.apply + persistence), which is
// distinct from checkGrantableScopes's "ShouldAllowOmittedScope" case (scope_test.go): that proves the ceiling check
// has nothing to reject when 'scope' is absent, not that the persisted client actually ends up scopeless.
func TestSpec_RFC7591_ScopeOmittedGrantsNone(t *testing.T) {
	ctx := context.Background()
	_, registrar, _, store := newConfigurationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	assert.NotContains(t, responder.ToMap(), "scope", "an omitted 'scope' must not be echoed back as granted")

	client, err := store.GetClient(ctx, responder.ClientID)
	require.NoError(t, err)
	assert.Empty(t, client.GetScopes(), "a client registered with no 'scope' must be persisted with no scopes")
}

// §2.1: "the authorization server responds with an HTTP 200 OK status code and a body ... containing the client
// metadata... The response body includes ALL of the client metadata currently associated with the client".
// TestClientConfigurationHandlerReads (handler_configuration_test.go) already proves a GET right after registration
// returns that metadata; this test proves the "currently" part - GET after an update must reflect the update, not
// what registration originally returned.
func TestSpec_RFC7592_2_1_ReadReturnsCurrentMetadata(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, _ := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	update := oauth2.NewClientConfigurationRequest()
	update.Method = http.MethodPut
	update.ClientID = id
	update.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/updated"},
		ClientName:   "Updated Name",
	}

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, update, oauth2.NewClientRegistrationResponse()))

	read := oauth2.NewClientConfigurationRequest()
	read.Method = http.MethodGet
	read.ClientID = id

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, read, responder))

	values := responder.ToMap()
	assert.Equal(t, http.StatusOK, responder.GetStatusCode())
	assert.Equal(t, "Updated Name", values["client_name"], "GET must reflect metadata set by the prior PUT, not the original registration")
	assert.Equal(t, []any{"https://example.com/updated"}, values["redirect_uris"])
	assert.Equal(t, ClientConfigurationURL(testEndpoint, id), values["registration_client_uri"])
}

// §3: "All requests to the client configuration endpoint MUST be authenticated using the registration access token
// issued to the client and MUST be rejected if the registration access token has been revoked or is otherwise
// invalid. [...] the authorization server returns an HTTP 401 status code..."
//
// This exercises the client configuration endpoint specifically (a non-empty client_id in the path, i.e. the
// KindManage side of DefaultEndpointAuthStrategy): TestAuthRejectsUnknownToken and TestAuthRejectsOrdinaryAccessToken
// (strategy_auth_test.go) already prove the "unknown token" and "ordinary access token" cases reject with
// oauth2.ErrRequestUnauthorized, but only at the client registration endpoint (empty id); this proves the same two
// guards hold symmetrically at the configuration endpoint, and additionally pins the concrete 401 status code the
// spec names rather than just "an error".
func TestSpec_RFC7592_3_InvalidTokenReturns401(t *testing.T) {
	ctx := context.Background()

	assertUnauthorized := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, oauth2.ErrorToRFC6749Error(err).CodeField)
	}

	t.Run("UnknownToken", func(t *testing.T) {
		auth, _, _, _ := newAuthFixtures(t)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/target-client", "authelia_at_notreal.notreal"), "target-client")
		assertUnauthorized(t, err)
	})

	t.Run("OrdinaryAccessToken", func(t *testing.T) {
		auth, _, store, tokens := newAuthFixtures(t)

		requester := oauth2.NewRequest()
		requester.Client = &oauth2.DefaultClient{ID: "target-client"}
		requester.Session = &oauth2.DefaultSession{Subject: "target-client"}
		requester.GrantAudience(ClientConfigurationURL("https://auth.example.com/register", "target-client"))

		token, signature, err := tokens.GenerateAccessToken(ctx, requester)
		require.NoError(t, err)
		require.NoError(t, store.CreateAccessTokenSession(ctx, signature, requester))

		_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/target-client", token), "target-client")
		assertUnauthorized(t, err)
	})

	t.Run("CreationTokenAtConfigurationEndpoint", func(t *testing.T) {
		auth, config, store, tokens := newAuthFixtures(t)

		token, err := NewClientCreationToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "target-client"}, nil)
		require.NoError(t, err)

		_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/target-client", token), "target-client")
		assertUnauthorized(t, err)
	})
}

// OpenID Connect Dynamic Client Registration 1.0 §2: "token_endpoint_auth_method [...] OPTIONAL. [...] If unspecified
// or omitted, the default is 'client_secret_basic'".
func TestSpec_OIDCDCR_2_DefaultTokenEndpointAuthMethod(t *testing.T) {
	ctx := context.Background()
	_, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)

	client, err := store.GetClient(ctx, created["client_id"].(string))
	require.NoError(t, err)

	authMethodClient, ok := client.(oauth2.AuthenticationMethodClient)
	require.True(t, ok)
	assert.Equal(t, "client_secret_basic", authMethodClient.GetTokenEndpointAuthMethod())
}

// §2: "application_type [...] OPTIONAL. [...] The default, if omitted, is 'web'." A 'web' client's redirect URIs
// must use 'https' (validateRedirectURIs in validator_local.go); this proves that rule applies even when
// 'application_type' is never set to 'web' explicitly, i.e. that omission really does default to 'web' rather than
// to some more permissive unrecognized-type behavior.
func TestSpec_OIDCDCR_2_DefaultApplicationTypeIsWeb(t *testing.T) {
	config := &oauth2.Config{ScopeStrategy: oauth2.ExactScopeStrategy, AudienceStrategy: oauth2.DefaultAudienceStrategy}
	validator := NewLocalValidator(config)

	metadata := &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"http://127.0.0.1:8080/cb"},
	}

	err := validator.ValidateClientRegistrationMetadata(context.Background(), nil, metadata)
	require.Error(t, err, "an omitted 'application_type' must default to 'web' and therefore reject a non-https redirect URI")
	assert.Equal(t, "invalid_redirect_uri", oauth2.ErrorToRFC6749Error(err).ErrorField)
}
