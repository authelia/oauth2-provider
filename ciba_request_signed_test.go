// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaSignedTestClientES256        = "signed-es256"
	cibaSignedTestClientHS256        = "signed-hs256"
	cibaSignedTestClientUnregistered = "signed-unregistered"
)

func TestBackChannelSignedRequest(t *testing.T) {
	testCases := []struct {
		name    string
		client  string
		claims  func(claims jwt.MapClaims)
		form    func(form url.Values)
		request func(t *testing.T, claims jwt.MapClaims, key *ecdsa.PrivateKey) string
		replay  bool
		used    bool
		err     *RFC6749Error
		hint    string
		check   func(t *testing.T, requester BackChannelAuthenticationRequester)
	}{
		{
			name: "ShouldDecodeTheParameters",
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				form := requester.GetRequestForm()

				assert.Equal(t, "openid profile", form.Get(consts.FormParameterScope))
				assert.Equal(t, "W4SCT", requester.GetBindingMessage())
				assert.False(t, form.Has(consts.FormParameterRequest))
				assert.False(t, form.Has(consts.ClaimJWTID))
				assert.False(t, form.Has(consts.ClaimIssuer))

				kind, value := requester.GetHint()
				assert.Equal(t, CIBAHintKindLoginHint, kind)
				assert.Equal(t, "alice", value)
				assert.Equal(t, 120*time.Second, requester.GetRequestedExpiry())
				assert.JSONEq(t, `{"amount":10,"nested":{"a":[1,2]}}`, string(requester.GetRequestContext()))
			},
		},
		{
			name:   "ShouldAcceptRequestedExpiryAsAString",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = "120" },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, 120*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name:   "ShouldAcceptRequestedExpiryAsAJSONNumberWithAFraction",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = json.RawMessage("120.0") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, 120*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name:   "ShouldAcceptRequestedExpiryAsAJSONNumberWithAnExponent",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = json.RawMessage("1.2e2") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, 120*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name:   "ShouldKeepAnOverflowingRequestedExpiryClaimAsTheMaximum",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = json.RawMessage("1.5e20") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, time.Duration(math.MaxInt64/int64(time.Second))*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name: "ShouldKeepALargeRequestedExpiryClaimAsTheMaximum",
			claims: func(claims jwt.MapClaims) {
				claims[consts.FormParameterRequestedExpiry] = json.RawMessage("99999999999999999999")
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, time.Duration(math.MaxInt64/int64(time.Second))*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name:   "ShouldRejectANonIntegralRequestedExpiry",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = json.RawMessage("120.5") },
			err:    ErrInvalidRequest,
			hint:   "'requested_expiry'",
		},
		{
			name:   "ShouldRejectANegativeRequestedExpiry",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = -120 },
			err:    ErrInvalidRequest,
			hint:   "'requested_expiry'",
		},
		{
			name:   "ShouldRejectAZeroRequestedExpiry",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = 0 },
			err:    ErrInvalidRequest,
			hint:   "'requested_expiry'",
		},
		{
			name:   "ShouldRejectABooleanRequestedExpiry",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestedExpiry] = true },
			err:    ErrInvalidRequest,
			hint:   "'requested_expiry'",
		},
		{
			name: "ShouldDropThePromptAndMaxAgeClaims",
			claims: func(claims jwt.MapClaims) {
				claims[consts.FormParameterPrompt] = consts.PromptTypeNone
				claims[consts.FormParameterMaximumAge] = 0
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterPrompt))
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterMaximumAge))
			},
		},
		{
			name: "ShouldAcceptAJTIUsedByAClientAssertion",
			used: true,
		},
		{
			name: "ShouldRejectAJWE",
			request: func(_ *testing.T, _ jwt.MapClaims, _ *ecdsa.PrivateKey) string {
				return "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..aaaa.bbbb.cccc"
			},
			err:  ErrInvalidRequest,
			hint: "must be signed and not encrypted",
		},
		{
			name:   "ShouldRejectHS256",
			client: cibaSignedTestClientHS256,
			request: func(t *testing.T, claims jwt.MapClaims, _ *ecdsa.PrivateKey) string {
				claims[jwt.ClaimIssuer] = cibaSignedTestClientHS256

				return mustGenerateClientAssertion(t, claims, jose.HS256, "", "", []byte(cibaTestSecret))
			},
			err:  ErrInvalidRequest,
			hint: "asymmetric",
		},
		{
			name: "ShouldRejectAnAlgDifferingFromTheRegisteredAlg",
			request: func(t *testing.T, claims jwt.MapClaims, _ *ecdsa.PrivateKey) string {
				return mustGenerateClientAssertion(t, claims, jose.ES512, "", cibaTestKID, gen.MustES521Key())
			},
			err:  ErrInvalidRequest,
			hint: "could not be verified",
		},
		{
			name:   "ShouldRejectAMissingJTI",
			claims: func(claims jwt.MapClaims) { delete(claims, jwt.ClaimJWTID) },
			err:    ErrInvalidRequest,
			hint:   "'jti'",
		},
		{
			name:   "ShouldRejectAMissingNotBefore",
			claims: func(claims jwt.MapClaims) { delete(claims, jwt.ClaimNotBefore) },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name:   "ShouldRejectAMissingExpirationTime",
			claims: func(claims jwt.MapClaims) { delete(claims, jwt.ClaimExpirationTime) },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name:   "ShouldRejectAMissingIssuedAt",
			claims: func(claims jwt.MapClaims) { delete(claims, jwt.ClaimIssuedAt) },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name:   "ShouldRejectAnExpiredRequest",
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimExpirationTime] = time.Now().Add(-time.Minute).Unix() },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name:   "ShouldRejectAnAudienceOfTheTokenURLOnly",
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimAudience] = []string{cibaTestIssuer + "/token"} },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name: "ShouldAcceptAnAudienceContainingTheIssuer",
			claims: func(claims jwt.MapClaims) {
				claims[jwt.ClaimAudience] = []string{cibaTestURL, cibaTestIssuer}
			},
		},
		{
			name:   "ShouldRejectAnotherClientAsTheIssuer",
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimIssuer] = cibaTestClientOther },
			err:    ErrInvalidRequest,
			hint:   "invalid claims",
		},
		{
			name: "ShouldRejectALoginHintAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterLoginHint, "alice") },
			err:  ErrInvalidRequest,
			hint: "'login_hint'",
		},
		{
			name: "ShouldIgnoreAnUnrecognisedParameterOutsideTheRequest",
			form: func(form url.Values) {
				form.Set("foo", "bar")
				form.Set(consts.FormParameterPrompt, consts.PromptTypeNone)
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				form := requester.GetRequestForm()

				assert.False(t, form.Has("foo"))
				assert.False(t, form.Has(consts.FormParameterPrompt))
				assert.Equal(t, "openid profile", form.Get(consts.FormParameterScope))
			},
		},
		{
			name: "ShouldKeepTheClientIDOutsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterClientID, cibaSignedTestClientES256) },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, cibaSignedTestClientES256, requester.GetRequestForm().Get(consts.FormParameterClientID))
			},
		},
		{
			name: "ShouldRejectANonceAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterNonce, "nonce-value") },
			err:  ErrInvalidRequest,
			hint: "The 'nonce' parameter must not be included outside",
		},
		{
			name: "ShouldRejectADPoPJKTAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterDPoPJKT, "jkt") },
			err:  ErrInvalidRequest,
			hint: "The 'dpop_jkt' parameter must not be included outside",
		},
		{
			name: "ShouldRejectClaimsAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterClaims, `{"id_token":{}}`) },
			err:  ErrInvalidRequest,
			hint: "The 'claims' parameter must not be included outside",
		},
		{
			name: "ShouldRejectAResourceAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterResource, "https://rs.example.com") },
			err:  ErrInvalidRequest,
			hint: "The 'resource' parameter must not be included outside",
		},
		{
			name: "ShouldRejectAuthorizationDetailsAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterAuthorizationDetails, `[]`) },
			err:  ErrInvalidRequest,
			hint: "The 'authorization_details' parameter must not be included outside",
		},
		{
			name: "ShouldRejectARequestContextAlongsideTheRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestContext, `{}`) },
			err:  ErrInvalidRequest,
			hint: "The 'request_context' parameter must not be included outside",
		},
		{
			name:   "ShouldRejectAReplayedJTI",
			replay: true,
			err:    ErrInvalidRequest,
			hint:   "'jti'",
		},
		{
			name: "ShouldRejectAnUnsignedRequestFromAClientRegisteredWithAnAlg",
			request: func(_ *testing.T, _ jwt.MapClaims, _ *ecdsa.PrivateKey) string {
				return ""
			},
			form: func(form url.Values) {
				form.Set(consts.FormParameterScope, "openid")
				form.Set(consts.FormParameterLoginHint, "alice")
			},
			err:  ErrInvalidRequest,
			hint: "must send a signed authentication request",
		},
		{
			name:   "ShouldRejectARequestFromAClientNotRegisteredWithAnAlg",
			client: cibaSignedTestClientUnregistered,
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimIssuer] = cibaSignedTestClientUnregistered },
			err:    ErrInvalidRequest,
			hint:   "backchannel_authentication_request_signing_alg",
		},
		{
			name:   "ShouldRejectTwoHints",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterLoginHintToken] = "token" },
			err:    ErrInvalidRequest,
			hint:   "Exactly one of",
		},
		{
			name:   "ShouldRejectARequestContextWhichIsNotAnObject",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestContext] = []string{"a"} },
			err:    ErrInvalidRequest,
			hint:   "'request_context'",
		},
		{
			name:   "ShouldRejectARequestClaim",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequest] = "a.b.c" },
			err:    ErrInvalidRequest,
			hint:   "must not include the 'request' claim",
		},
	}

	stores := map[string]func() (Storage, *storage.MemoryStore){
		"MemoryStore": func() (Storage, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		},
		"HydratingMemoryStore": func() (Storage, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		},
	}

	key := gen.MustES256Key()

	for storeName, newStore := range stores {
		t.Run(storeName, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					provider := newCIBASignedTestProvider(newStore, key)

					client := tc.client
					if client == "" {
						client = cibaSignedTestClientES256
					}

					now := time.Now()

					claims := jwt.MapClaims{
						jwt.ClaimIssuer:                     cibaSignedTestClientES256,
						jwt.ClaimAudience:                   cibaTestIssuer,
						jwt.ClaimExpirationTime:             now.Add(5 * time.Minute).Unix(),
						jwt.ClaimIssuedAt:                   now.Unix(),
						jwt.ClaimNotBefore:                  now.Unix(),
						jwt.ClaimJWTID:                      "jti-" + tc.name,
						consts.FormParameterScope:           "openid profile",
						consts.FormParameterLoginHint:       "alice",
						consts.FormParameterBindingMessage:  "W4SCT",
						consts.FormParameterRequestedExpiry: 120,
						consts.FormParameterRequestContext:  map[string]any{"amount": 10, "nested": map[string]any{"a": []int{1, 2}}},
					}

					if tc.claims != nil {
						tc.claims(claims)
					}

					var request string

					if tc.request != nil {
						request = tc.request(t, claims, key)
					} else {
						request = mustGenerateClientAssertion(t, claims, jose.ES256, "", cibaTestKID, key)
					}

					form := url.Values{}

					if request != "" {
						form.Set(consts.FormParameterRequest, request)
					}

					if tc.form != nil {
						tc.form(form)
					}

					send := func() (BackChannelAuthenticationRequester, error) {
						r := httptest.NewRequest(http.MethodPost, cibaTestURL, strings.NewReader(form.Encode()))
						r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
						r.SetBasicAuth(client, cibaTestSecret)

						return provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})
					}

					if tc.used {
						require.NoError(t, provider.Store.SetClientAssertionJWT(t.Context(), client, claims[jwt.ClaimJWTID].(string), now.Add(time.Hour)))
					}

					if tc.replay {
						_, err := send()
						require.NoError(t, ErrorToDebugRFC6749Error(err))
					}

					requester, err := send()

					if tc.err != nil {
						require.Error(t, err)

						rfc, ok := errors.AsType[*RFC6749Error](err)
						require.True(t, ok)
						assert.Equal(t, tc.err.ErrorField, rfc.ErrorField, "%+v", ErrorToDebugRFC6749Error(err))

						if tc.hint != "" {
							assert.Contains(t, rfc.HintField, tc.hint, "%+v", ErrorToDebugRFC6749Error(err))
						}

						return
					}

					require.NoError(t, ErrorToDebugRFC6749Error(err))

					if tc.check != nil {
						tc.check(t, requester)
					}
				})
			}
		})
	}
}

func newCIBASignedTestProvider(newStore func() (Storage, *storage.MemoryStore), key *ecdsa.PrivateKey) (provider *Fosite) {
	store, memory := newStore()

	config := &Config{
		Issuer:                      cibaTestIssuer,
		JWKSFetcherStrategy:         NewDefaultJWKSFetcherStrategy(),
		MinParameterEntropy:         8,
		EndpointURLs:                EndpointURLs{BackChannelAuthentication: cibaTestURL},
		CIBARequestSigningAlgValues: []string{string(jose.ES256), string(jose.HS256)},
	}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	config.JWTStrategy = jwtStrategy
	config.IDTokenValidationStrategy = &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	newClient := func(id, alg string) {
		memory.Clients[id] = &DefaultRegisteredClient{
			DefaultClient: &DefaultClient{
				ID:           id,
				ClientSecret: NewPlainTextClientSecret(cibaTestSecret),
				GrantTypes:   []string{consts.GrantTypeOpenIDCIBA},
				Scopes:       []string{"openid", "profile"},
			},
			TokenEndpointAuthMethod:                    consts.ClientAuthMethodClientSecretBasic,
			BackChannelTokenDeliveryMode:               consts.CIBAModePoll,
			BackChannelAuthenticationRequestSigningAlg: alg,
			JSONWebKeys: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{{KeyID: cibaTestKID, Use: "sig", Algorithm: string(jose.ES256), Key: &key.PublicKey}},
			},
		}
	}

	newClient(cibaSignedTestClientES256, string(jose.ES256))
	newClient(cibaSignedTestClientHS256, string(jose.HS256))
	newClient(cibaSignedTestClientUnregistered, "")
	newClient(cibaTestClientOther, string(jose.ES256))

	return &Fosite{Store: store, Config: config}
}
