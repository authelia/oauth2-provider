// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaTestClientID     = "ciba-client"
	cibaTestSubject      = "john"
	cibaTestScopeProfile = "profile"
	cibaTestNonce        = "nonce-value-0123456789"
)

type cibaOpenIDTestStore interface {
	ciba.Storage
	oauth2.Storage
	hoauth2.CoreStorage
	hoauth2.TokenRevocationStorage
	openid.OpenIDConnectRequestStorage
}

var cibaOpenIDTestStores = []struct {
	name string
	new  func() (cibaOpenIDTestStore, *storage.MemoryStore)
}{
	{"MemoryStore", func() (cibaOpenIDTestStore, *storage.MemoryStore) {
		store := storage.NewMemoryStore()

		return store, store
	}},
	{"HydratingMemoryStore", func() (cibaOpenIDTestStore, *storage.MemoryStore) {
		store := storage.NewHydratingMemoryStore()

		return store, store.MemoryStore
	}},
}

type cibaOpenIDFixture struct {
	store    cibaOpenIDTestStore
	config   *oauth2.Config
	provider *oauth2.Fosite
	handler  *openid.OpenIDConnectCIBAHandler
	client   *oauth2.DefaultCIBAClient
}

func newCIBAOpenIDFixture(t *testing.T, newStore func() (cibaOpenIDTestStore, *storage.MemoryStore)) *cibaOpenIDFixture {
	t.Helper()

	store, memory := newStore()

	config := &oauth2.Config{
		GlobalSecret:        []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
		Issuer:              "https://op.example.com",
		AccessTokenLifespan: time.Hour,
		IDTokenLifespan:     time.Hour,
		MinParameterEntropy: 8,
	}

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	tokenHandler := &ciba.TokenHandler{Storage: store, Strategy: strategy, Config: config}

	handler := &openid.OpenIDConnectCIBAHandler{
		OpenIDConnectRequestStorage: store,
		CodeTokenEndpointHandler:    tokenHandler,
		Config:                      config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: &openid.DefaultStrategy{
				Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
				Config:   config,
			},
		},
	}

	config.TokenEndpointHandlers.Append(&ciba.TokenEndpointHandler{
		GenericCodeTokenEndpointHandler: hoauth2.GenericCodeTokenEndpointHandler{
			CodeTokenEndpointHandler: tokenHandler,
			AccessTokenStrategy:      strategy,
			RefreshTokenStrategy:     strategy,
			CoreStorage:              store,
			TokenRevocationStorage:   store,
			Config:                   config,
		},
	})
	config.TokenEndpointHandlers.Append(handler)

	config.BackChannelAuthenticationEndpointHandlers.Append(handler)
	config.BackChannelAuthenticationEndpointHandlers.Append(&ciba.EndpointHandler{Storage: store, Strategy: strategy, Config: config})
	config.BackChannelAuthenticationDecisionHandlers.Append(&ciba.DecisionHandler{Storage: store, Strategy: strategy, Config: config})
	config.BackChannelAuthenticationDecisionHandlers.Append(handler)

	client := &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: consts.CIBAModePoll,
		DefaultClient: &oauth2.DefaultClient{
			ID:         cibaTestClientID,
			GrantTypes: oauth2.Arguments{consts.GrantTypeOpenIDCIBA},
			Scopes:     oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile},
		},
	}

	memory.Clients[client.GetID()] = client

	return &cibaOpenIDFixture{
		store:    store,
		config:   config,
		provider: &oauth2.Fosite{Store: store, Config: config},
		handler:  handler,
		client:   client,
	}
}

// request stores a pending backchannel authentication request for the subject with the scopes and form, and returns
// its 'auth_req_id' and request ID.
func (f *cibaOpenIDFixture) request(t *testing.T, scopes oauth2.Arguments, form url.Values) (authReqID, requestID string) {
	t.Helper()

	response, err := f.requestWithID(t, "request-id", scopes, form)
	require.NoError(t, err)

	return response.GetAuthRequestID(), "request-id"
}

// requestWithID makes a backchannel authentication request with the given request ID.
func (f *cibaOpenIDFixture) requestWithID(t *testing.T, requestID string, scopes oauth2.Arguments, form url.Values) (response oauth2.BackChannelAuthenticationResponder, err error) {
	t.Helper()

	session := openid.NewDefaultSession()
	session.Subject = cibaTestSubject
	session.Claims.Subject = cibaTestSubject

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID(requestID)
	request.Client = f.client
	request.DeliveryMode = consts.CIBAModePoll
	request.RequestedAt = time.Now().UTC()
	request.RequestedScope = scopes
	request.Session = session

	if form != nil {
		request.Form = form
	}

	return f.provider.NewBackChannelAuthenticationResponse(t.Context(), request)
}

// approve grants the scopes and approves the request with an approval session the configure function may change.
func (f *cibaOpenIDFixture) approve(t *testing.T, requestID string, scopes oauth2.Arguments, configure func(session *openid.DefaultSession)) {
	t.Helper()

	require.NoError(t, f.approveLoaded(t, f.load(t, requestID, scopes), configure))
}

// load loads the pending request for a decision and grants the scopes.
func (f *cibaOpenIDFixture) load(t *testing.T, requestID string, scopes oauth2.Arguments) oauth2.BackChannelAuthenticationRequester {
	t.Helper()

	loaded, err := f.provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), requestID, openid.NewDefaultSession())
	require.NoError(t, err)

	for _, scope := range scopes {
		loaded.GrantScope(scope)
	}

	return loaded
}

// approveLoaded approves the loaded request with an approval session the configure function may change.
func (f *cibaOpenIDFixture) approveLoaded(t *testing.T, loaded oauth2.BackChannelAuthenticationRequester, configure func(session *openid.DefaultSession)) (err error) {
	t.Helper()

	approval := openid.NewDefaultSession()
	approval.Subject = cibaTestSubject
	approval.Claims.Subject = cibaTestSubject
	approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	approval.RequestedAt = time.Now().UTC()

	if configure != nil {
		configure(approval)
	}

	_, err = f.provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)

	return err
}

// poll redeems the 'auth_req_id' at the token endpoint.
func (f *cibaOpenIDFixture) poll(t *testing.T, authReqID string) oauth2.AccessResponder {
	t.Helper()

	response, err := f.pollErr(t, authReqID)
	require.NoError(t, err)

	return response
}

// pollErr redeems the 'auth_req_id' at the token endpoint and returns the error of the token response.
func (f *cibaOpenIDFixture) pollErr(t *testing.T, authReqID string) (oauth2.AccessResponder, error) {
	t.Helper()

	request := oauth2.NewAccessRequest(openid.NewDefaultSession())
	request.Client = f.client
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeOpenIDCIBA}
	request.Form = url.Values{consts.FormParameterGrantType: {consts.GrantTypeOpenIDCIBA}, consts.FormParameterAuthReqID: {authReqID}}
	request.RequestedAt = time.Now().UTC()

	for _, handler := range f.config.GetTokenEndpointHandlers(t.Context()) {
		if !handler.CanHandleTokenEndpointRequest(t.Context(), request) {
			continue
		}

		if err := handler.HandleTokenEndpointRequest(t.Context(), request); err != nil && !errors.Is(err, oauth2.ErrUnknownRequest) {
			require.NoError(t, err)
		}
	}

	return f.provider.NewAccessResponse(t.Context(), request)
}

func decodeCIBATestIDToken(t *testing.T, token string) (claims map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims = map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

func TestOpenIDCIBAIssuesIDToken(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile}, nil)
			f.approve(t, requestID, oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile}, nil)

			response := f.poll(t, authReqID)

			token, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
			require.True(t, ok)
			require.NotEmpty(t, token)

			claims := decodeCIBATestIDToken(t, token)

			sum := sha256.Sum256([]byte(response.GetAccessToken()))

			assert.Equal(t, cibaTestSubject, claims[consts.ClaimSubject])
			assert.Equal(t, []any{cibaTestClientID}, claims[consts.ClaimAudience])
			assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), claims[consts.ClaimAccessTokenHash])
			assert.NotContains(t, claims, consts.ClaimCIBAAuthReqID)
			assert.NotContains(t, claims, consts.ClaimRefreshTokenHash)

			signature, err := f.handler.DeviceCodeSignature(t.Context(), authReqID)
			require.NoError(t, err)

			_, err = f.store.GetOpenIDConnectSession(t.Context(), signature, oauth2.NewRequest())
			assert.ErrorIs(t, err, openid.ErrNoSessionFound)
		})
	}
}

func TestOpenIDCIBAACR(t *testing.T) {
	testCases := []struct {
		name     string
		acr      string
		expected string
	}{
		{"ShouldConveyRecordedACR", oauth2.ACRPhishingResistant, oauth2.ACRPhishingResistant},
		{"ShouldConveyMinimumACRWhenNoneRecorded", "", oauth2.ACRMinimum},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaOpenIDTestStores {
				t.Run(sc.name, func(t *testing.T) {
					f := newCIBAOpenIDFixture(t, sc.new)

					authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID}, url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {"phr phrh"}})
					f.approve(t, requestID, oauth2.Arguments{consts.ScopeOpenID}, func(session *openid.DefaultSession) {
						session.Claims.AuthenticationContextClassReference = tc.acr
					})

					response := f.poll(t, authReqID)

					token, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
					require.True(t, ok)

					claims := decodeCIBATestIDToken(t, token)

					assert.Equal(t, tc.expected, claims[consts.ClaimAuthenticationContextClassReference])
				})
			}
		})
	}
}

func TestOpenIDCIBANoOpenIDScope(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)
			f.config.CIBADisableOpenIDScopeRequirement = true

			authReqID, requestID := f.request(t, oauth2.Arguments{cibaTestScopeProfile}, nil)
			f.approve(t, requestID, oauth2.Arguments{cibaTestScopeProfile}, nil)

			signature, err := f.handler.DeviceCodeSignature(t.Context(), authReqID)
			require.NoError(t, err)

			_, err = f.store.GetOpenIDConnectSession(t.Context(), signature, oauth2.NewRequest())
			assert.ErrorIs(t, err, openid.ErrNoSessionFound)

			response := f.poll(t, authReqID)

			assert.NotEmpty(t, response.GetAccessToken())
			assert.Nil(t, response.GetExtra(consts.AccessResponseIDToken))
		})
	}
}

func TestOpenIDCIBADecisionSkipsUndecidedOutcomes(t *testing.T) {
	testCases := []struct {
		name    string
		status  oauth2.CIBAStatus
		scopes  oauth2.Arguments
		grants  oauth2.Arguments
		foreign bool
	}{
		{"ShouldSkipDenied", oauth2.CIBAStatusDenied, oauth2.Arguments{consts.ScopeOpenID}, oauth2.Arguments{consts.ScopeOpenID}, false},
		{"ShouldSkipFailed", oauth2.CIBAStatusFailed, oauth2.Arguments{consts.ScopeOpenID}, oauth2.Arguments{consts.ScopeOpenID}, false},
		{"ShouldSkipPending", oauth2.CIBAStatusPending, oauth2.Arguments{consts.ScopeOpenID}, oauth2.Arguments{consts.ScopeOpenID}, false},
		{"ShouldSkipNoOpenIDScope", oauth2.CIBAStatusApproved, oauth2.Arguments{cibaTestScopeProfile}, oauth2.Arguments{cibaTestScopeProfile}, false},
		{"ShouldSkipClientWithoutGrantType", oauth2.CIBAStatusApproved, oauth2.Arguments{consts.ScopeOpenID}, oauth2.Arguments{consts.ScopeOpenID}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaOpenIDTestStores {
				t.Run(sc.name, func(t *testing.T) {
					f := newCIBAOpenIDFixture(t, sc.new)

					client := f.client

					if tc.foreign {
						client = &oauth2.DefaultCIBAClient{
							BackChannelTokenDeliveryMode: consts.CIBAModePoll,
							DefaultClient:                &oauth2.DefaultClient{ID: cibaTestClientID, GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}},
						}
					}

					session := openid.NewDefaultSession()
					session.Subject = cibaTestSubject
					session.Claims.Subject = cibaTestSubject

					request := oauth2.NewBackChannelAuthenticationRequest()
					request.Client = client
					request.RequestedScope = tc.scopes
					request.Session = session
					request.SetAuthRequestIDSignature("signature")
					request.SetStatus(tc.status)

					for _, scope := range tc.grants {
						request.GrantScope(scope)
					}

					require.NoError(t, f.handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{Status: tc.status}))

					_, err := f.store.GetOpenIDConnectSession(t.Context(), "signature", oauth2.NewRequest())
					assert.ErrorIs(t, err, openid.ErrNoSessionFound)
				})
			}
		})
	}
}

func TestOpenIDCIBADecisionWritesSession(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			session := openid.NewDefaultSession()
			session.Subject = cibaTestSubject
			session.Claims.Subject = cibaTestSubject

			request := oauth2.NewBackChannelAuthenticationRequest()
			request.Client = f.client
			request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
			request.GrantScope(consts.ScopeOpenID)
			request.Session = session
			request.Form = url.Values{
				consts.FormParameterAuthenticationContextClassReferenceValues: {oauth2.ACRPhishingResistant},
				consts.FormParameterBindingMessage:                            {"W4SCT"},
				consts.FormParameterLoginHint:                                 {"john@example.com"},
			}
			request.SetAuthRequestIDSignature("signature")
			request.SetStatus(oauth2.CIBAStatusApproved)

			require.NoError(t, f.handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{Status: oauth2.CIBAStatusApproved}))

			stored, err := f.store.GetOpenIDConnectSession(t.Context(), "signature", &oauth2.Request{Session: openid.NewDefaultSession()})
			require.NoError(t, err)

			assert.Equal(t, oauth2.ACRPhishingResistant, stored.GetRequestForm().Get(consts.FormParameterAuthenticationContextClassReferenceValues))
			assert.False(t, stored.GetRequestForm().Has(consts.FormParameterBindingMessage))
			assert.False(t, stored.GetRequestForm().Has(consts.FormParameterLoginHint))
			assert.Equal(t, cibaTestSubject, stored.GetSession().GetSubject())
		})
	}
}

func TestOpenIDCIBADecisionRequiresSignature(t *testing.T) {
	f := newCIBAOpenIDFixture(t, cibaOpenIDTestStores[0].new)

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Client = f.client
	request.GrantScope(consts.ScopeOpenID)
	request.Session = openid.NewDefaultSession()
	request.SetStatus(oauth2.CIBAStatusApproved)

	err := f.handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{Status: oauth2.CIBAStatusApproved})

	assert.ErrorIs(t, err, oauth2.ErrMisconfiguration)
}

func TestOpenIDCIBATokenEndpointIgnoresOtherGrants(t *testing.T) {
	f := newCIBAOpenIDFixture(t, cibaOpenIDTestStores[0].new)

	request := oauth2.NewAccessRequest(openid.NewDefaultSession())
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}

	assert.False(t, f.handler.CanHandleTokenEndpointRequest(t.Context(), request))
	assert.ErrorIs(t, f.handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrUnknownRequest)
	assert.ErrorIs(t, f.handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), oauth2.ErrUnknownRequest)
	assert.False(t, f.handler.CanSkipClientAuth(t.Context(), request))
}

func TestOpenIDCIBALosingApprovalWritesNoSession(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID}, nil)

			winner := f.load(t, requestID, oauth2.Arguments{consts.ScopeOpenID})
			loser := f.load(t, requestID, oauth2.Arguments{consts.ScopeOpenID})

			require.NoError(t, f.approveLoaded(t, winner, func(session *openid.DefaultSession) {
				session.Claims.AuthenticationContextClassReference = oauth2.ACRPhishingResistant
			}))

			assert.ErrorIs(t, f.approveLoaded(t, loser, func(session *openid.DefaultSession) {
				session.Claims.AuthenticationContextClassReference = oauth2.ACRPhishingResistantHardware
			}), oauth2.ErrInvalidRequest)

			response := f.poll(t, authReqID)

			token, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
			require.True(t, ok)

			assert.Equal(t, oauth2.ACRPhishingResistant, decodeCIBATestIDToken(t, token)[consts.ClaimAuthenticationContextClassReference])
		})
	}
}

func TestOpenIDCIBADecisionStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)

	store := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	store.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "signature", gomock.Any()).Return(errors.New("database unavailable"))

	handler := &openid.OpenIDConnectCIBAHandler{OpenIDConnectRequestStorage: store, Config: &oauth2.Config{}}

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Client = &oauth2.DefaultClient{ID: cibaTestClientID, GrantTypes: oauth2.Arguments{consts.GrantTypeOpenIDCIBA}}
	request.GrantScope(consts.ScopeOpenID)
	request.Session = openid.NewDefaultSession()
	request.SetAuthRequestIDSignature("signature")
	request.SetStatus(oauth2.CIBAStatusApproved)

	err := handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{Status: oauth2.CIBAStatusApproved})

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestOpenIDCIBANonceReuseRejectedAtEndpoint(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			form := func() url.Values {
				return url.Values{consts.FormParameterNonce: {cibaTestNonce}}
			}

			_, err := f.requestWithID(t, "request-1", oauth2.Arguments{consts.ScopeOpenID}, form())
			require.NoError(t, err)

			_, err = f.requestWithID(t, "request-2", oauth2.Arguments{consts.ScopeOpenID}, form())
			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)

			_, err = f.store.GetCIBASessionByRequestID(t.Context(), "request-2", openid.NewDefaultSession())
			assert.ErrorIs(t, err, oauth2.ErrNotFound)

			_, err = f.requestWithID(t, "request-3", oauth2.Arguments{cibaTestScopeProfile}, form())
			assert.NoError(t, err)
		})
	}
}

func TestOpenIDCIBADecisionDoesNotRecordNonce(t *testing.T) {
	ctrl := gomock.NewController(t)

	store := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	store.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "signature", gomock.Any()).Return(nil)

	handler := &openid.OpenIDConnectCIBAHandler{OpenIDConnectRequestStorage: store, Config: &oauth2.Config{}}

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Client = &oauth2.DefaultClient{ID: cibaTestClientID, GrantTypes: oauth2.Arguments{consts.GrantTypeOpenIDCIBA}}
	request.GrantScope(consts.ScopeOpenID)
	request.Form = url.Values{consts.FormParameterNonce: {cibaTestNonce}}
	request.Session = openid.NewDefaultSession()
	request.SetAuthRequestIDSignature("signature")
	request.SetStatus(oauth2.CIBAStatusApproved)

	assert.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{Status: oauth2.CIBAStatusApproved}))
}

func TestOpenIDCIBAMissingSessionFailsClosed(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID}, nil)
			f.approve(t, requestID, oauth2.Arguments{consts.ScopeOpenID}, nil)

			signature, err := f.handler.DeviceCodeSignature(t.Context(), authReqID)
			require.NoError(t, err)

			require.NoError(t, f.store.DeleteOpenIDConnectSession(t.Context(), signature))

			response, err := f.pollErr(t, authReqID)

			assert.Nil(t, response)
			assert.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).DebugField, "OpenID Connect session missing for an approved CIBA request that granted openid")
		})
	}
}

func TestOpenIDCIBARequestedOpenIDNotGrantedFailsClosed(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile}, nil)

			loaded := f.load(t, requestID, oauth2.Arguments{cibaTestScopeProfile})
			loaded.SetStatus(oauth2.CIBAStatusApproved)

			require.NoError(t, f.store.DecideCIBASession(t.Context(), loaded.GetAuthRequestIDSignature(), loaded))

			response, err := f.pollErr(t, authReqID)

			assert.Nil(t, response)
			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).DebugField, "The 'openid' scope was requested but not granted")
		})
	}
}

func TestOpenIDCIBAIgnoresIDTokenHintAtIssuance(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			rotated := &jwt.DefaultStrategy{Config: f.config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

			hint, _, err := rotated.Encode(t.Context(), jwt.MapClaims{
				consts.ClaimIssuer:         f.config.Issuer,
				consts.ClaimSubject:        cibaTestSubject,
				consts.ClaimAudience:       []string{cibaTestClientID},
				consts.ClaimIssuedAt:       time.Now().Add(-time.Hour).Unix(),
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
			}, jwt.WithClient(jwt.NewIDTokenClient(f.client)))
			require.NoError(t, err)

			authReqID, requestID := f.request(t, oauth2.Arguments{consts.ScopeOpenID}, url.Values{consts.FormParameterIDTokenHint: {hint}})
			f.approve(t, requestID, oauth2.Arguments{consts.ScopeOpenID}, nil)

			response := f.poll(t, authReqID)

			token, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
			require.True(t, ok)

			assert.Equal(t, cibaTestSubject, decodeCIBATestIDToken(t, token)[consts.ClaimSubject])
		})
	}
}
