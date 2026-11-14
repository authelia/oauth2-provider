// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaClientID           = "ciba-client"
	cibaKeyBindingClientID = "ciba-key-binding-client"
	cibaMTLSClientID       = "ciba-mtls-client"
	cibaMTLSSubjectDN      = "CN=ciba-mtls-client"
	cibaCertificateHdr     = "X-Client-Certificate"
	cibaScope              = consts.ScopeOpenID + " " + consts.ScopeOffline
)

func TestCIBAPollFlow(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			flow := newCIBAFlow(t, st.new)

			t.Run("ShouldIssueTokensOncePollingClientIsApproved", func(t *testing.T) {
				id := flow.authenticate(t, cibaClientID, nil)

				status, body := flow.poll(t, cibaClientID, id, nil)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "authorization_pending", body["error"])

				flow.approve(t)

				status, body = flow.poll(t, cibaClientID, id, nil)
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)

				assert.Equal(t, "bearer", strings.ToLower(body["token_type"].(string)))
				assert.NotEmpty(t, body["access_token"])
				assert.NotEmpty(t, body["refresh_token"])
				require.NotEmpty(t, body["id_token"])

				claims := cibaDecodeClaims(t, body["id_token"].(string))
				assert.Equal(t, testSubject, claims[consts.ClaimSubject])
				assert.Equal(t, cibaClientID, claims[consts.ClaimAudience].([]any)[0])
				assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])

				status, refreshed := flow.token(t, cibaClientID, url.Values{
					consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
					consts.FormParameterRefreshToken: {body["refresh_token"].(string)},
				}, nil)
				require.Equal(t, http.StatusOK, status, "refresh error: %+v", refreshed)
				assert.NotEmpty(t, refreshed["access_token"])
				assert.NotEqual(t, body["access_token"], refreshed["access_token"])

				status, body = flow.poll(t, cibaClientID, id, nil)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_grant", body["error"])
			})

			t.Run("ShouldBindTheTokensToTheTLSClientAuthCertificate", func(t *testing.T) {
				certificate := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: cibaMTLSClientID}})

				opts := &cibaRequestOptions{certificate: certificate}

				id := flow.authenticate(t, cibaMTLSClientID, opts)

				flow.approve(t)

				status, body := flow.poll(t, cibaMTLSClientID, id, opts)
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				assert.NotEmpty(t, body["id_token"])

				_, requester, err := flow.provider.IntrospectToken(context.Background(), body["access_token"].(string), oauth2.AccessToken, openid.NewDefaultSession())
				require.NoError(t, err)

				session, ok := requester.GetSession().(oauth2.MTLSBoundSession)
				require.True(t, ok)
				assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(certificate), session.GetClientCertificateSHA256Thumbprint())
			})

			t.Run("ShouldBindTheTokensToTheDPoPProof", func(t *testing.T) {
				key := newDPoPProofKey(t)

				id := flow.authenticate(t, cibaClientID, nil)

				flow.approve(t)

				status, body := flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				assert.Equal(t, oauth2.DPoPAccessToken, body["token_type"])
				assert.NotEmpty(t, body["id_token"])
			})
		})
	}
}

// cibaMTLSClient is a poll mode CIBA client which authenticates with 'tls_client_auth'.
type cibaMTLSClient struct {
	*oauth2.DefaultMTLSClient
}

func (c *cibaMTLSClient) GetBackChannelTokenDeliveryMode() string { return consts.CIBAModePoll }

func (c *cibaMTLSClient) GetBackChannelClientNotificationEndpoint() string { return "" }

func (c *cibaMTLSClient) GetBackChannelAuthenticationRequestSigningAlg() string { return "" }

func (c *cibaMTLSClient) GetBackChannelUserCodeParameter() bool { return false }

type cibaRequestOptions struct {
	certificate *x509.Certificate
	dpop        string
	form        url.Values
}

type cibaFlow struct {
	ts       *httptest.Server
	provider oauth2.Provider
	key      *rsa.PrivateKey

	mu      sync.Mutex
	pending string
}

func newCIBAFlow(t *testing.T, newStore func() (any, map[string]oauth2.Client), configure ...func(*oauth2.Config)) *cibaFlow {
	t.Helper()

	store, clients := newStore()

	clients[cibaClientID] = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: consts.CIBAModePoll,
		DefaultClient: &oauth2.DefaultClient{
			ID:           cibaClientID,
			ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
			GrantTypes:   []string{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
			Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline},
		},
	}

	clients[cibaKeyBindingClientID] = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: consts.CIBAModePoll,
		DefaultClient: &oauth2.DefaultClient{
			ID:           cibaKeyBindingClientID,
			ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
			GrantTypes:   []string{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
			Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline, consts.ScopeBoundKey},
		},
	}

	clients[cibaMTLSClientID] = &cibaMTLSClient{
		DefaultMTLSClient: &oauth2.DefaultMTLSClient{
			TLSClientAuthSubjectDN: cibaMTLSSubjectDN,
			DefaultJARClient: &oauth2.DefaultJARClient{
				TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
				DefaultClient: &oauth2.DefaultClient{
					ID:                                    cibaMTLSClientID,
					GrantTypes:                            []string{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
					Scopes:                                []string{consts.ScopeOpenID, consts.ScopeOffline},
					TLSClientCertificateBoundAccessTokens: true,
				},
			},
		},
	}

	config := &oauth2.Config{
		GlobalSecret:                []byte("ciba-integration-test-secret-32-bytes"),
		CIBAPollingInterval:         time.Nanosecond,
		DPoPEnabled:                 true,
		MTLSEnabled:                 true,
		MTLSClientCertificateHeader: cibaCertificateHdr,
	}

	for _, fn := range configure {
		fn(config)
	}

	key := gen.MustRSAKey()
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	flow := &cibaFlow{key: key}

	flow.provider = compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
			Strategy:                   strategy,
		},
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,

		compose.CIBADecisionFactory,
		compose.CIBATokenFactory,
		compose.OpenIDConnectCIBAFactory,
		compose.CIBAEndpointFactory,

		compose.OpenIDConnectRefreshFactory,

		compose.DPoPTokenFactory,
		compose.RFC8705Factory,
		compose.OpenIDConnectKeyBindingFactory,
	)

	router := http.NewServeMux()

	router.HandleFunc("/bc-authorize", func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		session := openid.NewDefaultSession()

		request, err := flow.provider.NewBackChannelAuthenticationRequest(ctx, req, session)
		if err != nil {
			flow.provider.WriteBackChannelAuthenticationError(ctx, rw, request, err)
			return
		}

		// The application resolves the end user from the hint.
		session.Subject = request.GetRequestForm().Get(consts.FormParameterLoginHint)
		session.Claims.Subject = session.Subject

		if r, ok := request.(*oauth2.BackChannelAuthenticationRequest); ok {
			r.RequestedAt = r.RequestedAt.Add(-time.Minute)
		}

		response, err := flow.provider.NewBackChannelAuthenticationResponse(ctx, request)
		if err != nil {
			flow.provider.WriteBackChannelAuthenticationError(ctx, rw, request, err)
			return
		}

		flow.mu.Lock()
		flow.pending = request.GetID()
		flow.mu.Unlock()

		flow.provider.WriteBackChannelAuthenticationResponse(ctx, rw, request, response)
	})

	router.HandleFunc(tokenRelativePath, func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		requester, err := flow.provider.NewAccessRequest(ctx, req, openid.NewDefaultSession())
		if err != nil {
			flow.provider.WriteAccessError(ctx, rw, requester, err)
			return
		}

		response, err := flow.provider.NewAccessResponse(ctx, requester)
		if err != nil {
			flow.provider.WriteAccessError(ctx, rw, requester, err)
			return
		}

		flow.provider.WriteAccessResponse(ctx, rw, requester, response)
	})

	flow.ts = httptest.NewServer(router)

	t.Cleanup(flow.ts.Close)

	return flow
}

// authenticate makes a backchannel authentication request for the test subject and returns the 'auth_req_id'.
func (f *cibaFlow) authenticate(t *testing.T, clientID string, opts *cibaRequestOptions) (id string) {
	t.Helper()

	status, body := f.backchannel(t, clientID, opts)
	require.Equal(t, http.StatusOK, status, "backchannel authentication error: %+v", body)

	id, _ = body[consts.FormParameterAuthReqID].(string)
	require.NotEmpty(t, id)

	return id
}

// backchannel makes a backchannel authentication request for the test subject and returns the response.
func (f *cibaFlow) backchannel(t *testing.T, clientID string, opts *cibaRequestOptions) (status int, body map[string]any) {
	t.Helper()

	form := url.Values{
		consts.FormParameterScope:     {cibaScope},
		consts.FormParameterLoginHint: {testSubject},
	}

	if opts != nil {
		for key, values := range opts.form {
			form[key] = values
		}
	}

	return f.post(t, "/bc-authorize", clientID, form, opts)
}

// approve records the end user's approval of the latest backchannel authentication request, granting every scope.
func (f *cibaFlow) approve(t *testing.T) {
	t.Helper()

	f.approveScopes(t, nil)
}

// approveScopes records the end user's approval of the latest backchannel authentication request, granting every
// requested scope except those withheld.
func (f *cibaFlow) approveScopes(t *testing.T, withheld []string) {
	t.Helper()

	f.mu.Lock()
	requestID := f.pending
	f.mu.Unlock()

	ctx := context.Background()

	request, err := f.provider.NewBackChannelAuthenticationDecisionRequest(ctx, requestID, openid.NewDefaultSession())
	require.NoError(t, err)

	for _, scope := range request.GetRequestedScopes() {
		if !slices.Contains(withheld, scope) {
			request.GrantScope(scope)
		}
	}

	approval := openid.NewDefaultSession()
	approval.Subject = testSubject
	approval.Claims.Subject = testSubject
	approval.Claims.AuthTime = jwt.NewNumericDate(time.Now())

	result, err := f.provider.ApproveBackChannelAuthentication(ctx, request, approval)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)
}

func (f *cibaFlow) poll(t *testing.T, clientID, id string, opts *cibaRequestOptions) (status int, body map[string]any) {
	t.Helper()

	return f.token(t, clientID, url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOpenIDCIBA},
		consts.FormParameterAuthReqID: {id},
	}, opts)
}

func (f *cibaFlow) token(t *testing.T, clientID string, form url.Values, opts *cibaRequestOptions) (status int, body map[string]any) {
	t.Helper()

	return f.post(t, tokenRelativePath, clientID, form, opts)
}

func (f *cibaFlow) post(t *testing.T, path, clientID string, form url.Values, opts *cibaRequestOptions) (status int, body map[string]any) {
	t.Helper()

	mtls := opts != nil && opts.certificate != nil

	// A 'tls_client_auth' client identifies itself with the 'client_id' parameter.
	if mtls {
		form.Set(consts.FormParameterClientID, clientID)
	}

	req, err := http.NewRequest(http.MethodPost, f.ts.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if mtls {
		req.Header.Set(cibaCertificateHdr, base64.StdEncoding.EncodeToString(opts.certificate.Raw))
	} else {
		req.SetBasicAuth(clientID, testClientSecret)
	}

	if opts != nil && opts.dpop != "" {
		req.Header.Set(consts.HeaderDPoP, opts.dpop)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body = map[string]any{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	return resp.StatusCode, body
}

func cibaDecodeClaims(t *testing.T, token string) (claims map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(raw, &claims))

	return claims
}
