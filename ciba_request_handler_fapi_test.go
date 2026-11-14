// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
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
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaFAPITestAuthorizationDetails = `[{"type":"payment_initiation","actions":["initiate"]}]`
	cibaFAPITestHintBindingMessage   = "The 'binding_message' parameter is required."
	cibaFAPITestBindingMessage       = "W4SCT"
	cibaFAPITestStoreMemory          = "MemoryStore"
	cibaFAPITestStoreHydrating       = "HydratingMemoryStore"
)

func TestFAPICIBABindingMessageUniqueAuthorizationContext(t *testing.T) {
	var (
		payment       = internal.PaymentInitiationTypeHandler{}
		unique        = &uniqueContextTypeHandler{PaymentInitiationTypeHandler: payment, unique: true}
		notUnique     = &uniqueContextTypeHandler{PaymentInitiationTypeHandler: payment}
		defaultUnique = &DefaultAuthorizationDetailsTypeHandler{Name: internal.AuthorizationDetailsTypePaymentInitiation, UniqueAuthorizationContext: true}
		defaultPlain  = &DefaultAuthorizationDetailsTypeHandler{Name: internal.AuthorizationDetailsTypePaymentInitiation}
	)

	withDetails := func(form url.Values) {
		form.Set(consts.FormParameterAuthorizationDetails, cibaFAPITestAuthorizationDetails)
	}

	testCases := []struct {
		name    string
		require bool
		handler AuthorizationDetailsTypeHandler
		form    func(form url.Values)
		err     *RFC6749Error
		hint    string
	}{
		{
			name:    "ShouldAcceptAUniqueContextWithoutABindingMessage",
			require: true,
			handler: unique,
			form:    withDetails,
		},
		{
			name:    "ShouldAcceptADefaultTypeDeclaredUniqueWithoutABindingMessage",
			require: true,
			handler: defaultUnique,
			form:    withDetails,
		},
		{
			name:    "ShouldRejectATypeWhichDoesNotDeclareAUniqueContext",
			require: true,
			handler: payment,
			form:    withDetails,
			err:     ErrInvalidRequest,
			hint:    cibaFAPITestHintBindingMessage,
		},
		{
			name:    "ShouldRejectADetailTheTypeReportsIsNotUnique",
			require: true,
			handler: notUnique,
			form:    withDetails,
			err:     ErrInvalidRequest,
			hint:    cibaFAPITestHintBindingMessage,
		},
		{
			name:    "ShouldRejectADefaultTypeNotDeclaredUnique",
			require: true,
			handler: defaultPlain,
			form:    withDetails,
			err:     ErrInvalidRequest,
			hint:    cibaFAPITestHintBindingMessage,
		},
		{
			name:    "ShouldAcceptABindingMessageWithoutAuthorizationDetails",
			require: true,
			handler: unique,
			form:    func(form url.Values) { form.Set(consts.FormParameterBindingMessage, cibaFAPITestBindingMessage) },
		},
		{
			name:    "ShouldRejectNeither",
			require: true,
			handler: unique,
			err:     ErrInvalidRequest,
			hint:    cibaFAPITestHintBindingMessage,
		},
		{
			name:    "ShouldRejectEmptyAuthorizationDetails",
			require: true,
			handler: unique,
			form:    func(form url.Values) { form.Set(consts.FormParameterAuthorizationDetails, `[]`) },
			err:     ErrInvalidAuthorizationDetails,
		},
		{
			name:    "ShouldRejectIgnoredAuthorizationDetailsWithoutABindingMessage",
			require: true,
			form:    withDetails,
			err:     ErrInvalidRequest,
			hint:    cibaFAPITestHintBindingMessage,
		},
		{
			name:    "ShouldStillValidateABindingMessageWithAUniqueContext",
			require: true,
			handler: unique,
			form: func(form url.Values) {
				withDetails(form)
				form.Set(consts.FormParameterBindingMessage, strings.Repeat("a", 65))
			},
			err: ErrInvalidBindingMessage,
		},
		{
			name:    "ShouldValidateTheBindingMessageBeforeAuthorizationDetails",
			handler: unique,
			form: func(form url.Values) {
				form.Set(consts.FormParameterAuthorizationDetails, "{")
				form.Set(consts.FormParameterBindingMessage, strings.Repeat("a", 65))
			},
			err: ErrInvalidBindingMessage,
		},
		{
			name:    "ShouldAcceptNeitherWithoutTheRequirement",
			handler: payment,
			form:    withDetails,
		},
	}

	key := gen.MustRSAKey()
	serverKey := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, _ := newCIBATestProvider(serverKey, key)
			config.CIBARequireBindingMessage = tc.require

			if tc.handler != nil {
				config.AuthorizationDetailsTypeHandlers = []AuthorizationDetailsTypeHandler{tc.handler}
			}

			requester, err := sendCIBAFAPITestRequest(t, provider, cibaTestClientPoll, tc.form)

			if tc.err != nil {
				assertCIBAFAPITestError(t, err, tc.err, tc.hint)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.NotNil(t, requester)
		})
	}
}

func TestFAPICIBARequestContextRequired(t *testing.T) {
	testCases := []struct {
		name    string
		require bool
		form    func(form url.Values)
		err     *RFC6749Error
	}{
		{
			name:    "ShouldRejectAMissingRequestContext",
			require: true,
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldAcceptARequestContext",
			require: true,
			form:    func(form url.Values) { form.Set(consts.FormParameterRequestContext, `{"geo":"x"}`) },
		},
		{
			name:    "ShouldRejectAnInvalidRequestContext",
			require: true,
			form:    func(form url.Values) { form.Set(consts.FormParameterRequestContext, `[]`) },
			err:     ErrInvalidRequest,
		},
		{
			name: "ShouldAcceptAMissingRequestContextWithoutTheRequirement",
		},
	}

	key := gen.MustRSAKey()
	serverKey := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, _ := newCIBATestProvider(serverKey, key)
			config.CIBARequireRequestContext = tc.require

			_, err := sendCIBAFAPITestRequest(t, provider, cibaTestClientPoll, tc.form)

			if tc.err != nil {
				assertCIBAFAPITestError(t, err, tc.err, "'request_context'")

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestFAPICIBARequestContextRequiredSigned(t *testing.T) {
	testCases := []struct {
		name   string
		claims func(claims jwt.MapClaims)
		err    *RFC6749Error
	}{
		{
			name: "ShouldAcceptARequestContextClaim",
		},
		{
			name:   "ShouldRejectAMissingRequestContextClaim",
			claims: func(claims jwt.MapClaims) { delete(claims, consts.FormParameterRequestContext) },
			err:    ErrInvalidRequest,
		},
		{
			name:   "ShouldRejectANullRequestContextClaim",
			claims: func(claims jwt.MapClaims) { claims[consts.FormParameterRequestContext] = nil },
			err:    ErrInvalidRequest,
		},
	}

	key := gen.MustES256Key()

	for storeName, newStore := range cibaFAPITestStores() {
		t.Run(storeName, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					provider := newCIBASignedTestProvider(newStore, key)
					provider.Config.(*Config).CIBARequireRequestContext = true

					now := time.Now()

					claims := newCIBAFAPITestSignedClaims(tc.name, now, now.Add(5*time.Minute))

					if tc.claims != nil {
						tc.claims(claims)
					}

					_, err := sendCIBAFAPITestSignedRequest(t, provider, key, claims)

					if tc.err != nil {
						assertCIBAFAPITestError(t, err, tc.err, "'request_context'")

						return
					}

					require.NoError(t, ErrorToDebugRFC6749Error(err))
				})
			}
		})
	}
}

func TestFAPICIBASignedRequestLifetime(t *testing.T) {
	testCases := []struct {
		name    string
		maximum time.Duration
		life    time.Duration
		err     *RFC6749Error
	}{
		{name: "ShouldRejectALifetimeOverTheMaximum", maximum: time.Hour, life: 61 * time.Minute, err: ErrInvalidRequest},
		{name: "ShouldAcceptALifetimeOfTheMaximum", maximum: time.Hour, life: time.Hour},
		{name: "ShouldAcceptAShortLifetime", maximum: time.Hour, life: time.Minute},
		{name: "ShouldRejectALifetimeOverTheRequestObjectMaximumWithoutAMaximum", life: 61 * time.Minute, err: ErrInvalidRequest},
		{name: "ShouldAcceptALifetimeOfTheRequestObjectMaximumWithoutAMaximum", life: time.Hour},
	}

	key := gen.MustES256Key()

	for storeName, newStore := range cibaFAPITestStores() {
		t.Run(storeName, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					provider := newCIBASignedTestProvider(newStore, key)
					provider.Config.(*Config).CIBASignedRequestMaximumLifetime = tc.maximum

					nbf := time.Now().Add(-time.Second)

					_, err := sendCIBAFAPITestSignedRequest(t, provider, key, newCIBAFAPITestSignedClaims(tc.name, nbf, nbf.Add(tc.life)))

					if tc.err != nil {
						assertCIBAFAPITestError(t, err, tc.err, "'nbf' and 'exp'")

						return
					}

					require.NoError(t, ErrorToDebugRFC6749Error(err))
				})
			}
		})
	}
}

func TestFAPICIBASingleAudience(t *testing.T) {
	testCases := []struct {
		name     string
		single   bool
		disable  bool
		endpoint string
		aud      any
		err      string
	}{
		{name: "ShouldRejectMultipleAudiences", single: true, disable: true, endpoint: audienceTestBackChannel, aud: []string{audienceTestIssuer, audienceTestTokenURL}, err: audienceTestErrSole},
		{name: "ShouldRejectTheBackChannelEndpointURL", single: true, disable: true, endpoint: audienceTestBackChannel, aud: audienceTestCIBAURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectTheTokenEndpointURLAudience", single: true, disable: true, endpoint: audienceTestBackChannel, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAudience", single: true, disable: true, endpoint: audienceTestBackChannel, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheIssuerInAnArray", single: true, disable: true, endpoint: audienceTestBackChannel, aud: []string{audienceTestIssuer}},
		{name: "ShouldRejectMultipleAudiencesWhenEnforcedGlobally", single: true, endpoint: audienceTestBackChannel, aud: []string{audienceTestIssuer, audienceTestTokenURL}, err: audienceTestErrSole},
		{name: "ShouldAcceptTheBackChannelEndpointURLWithoutTheRule", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestCIBAURL},
		{name: "ShouldRejectMultipleAudiencesWithoutTheRule", disable: true, endpoint: audienceTestBackChannel, aud: []string{audienceTestIssuer, audienceTestCIBAURL}, err: audienceTestErrSingle},
		{name: "ShouldNotApplyAtTheTokenEndpoint", single: true, disable: true, aud: audienceTestTokenURL},
	}

	key := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider := newAudienceTestProvider(key)
			config.DisableClientAssertionIssuerAudience = tc.disable
			config.CIBARequireSingleAudienceAssertion = tc.single

			form := url.Values{
				consts.FormParameterClientAssertion:     {newAudienceTestAssertion(t, key, "", "", tc.aud)},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
			}

			err := authenticateAudienceTestClient(t, config, provider, tc.endpoint, form)

			if tc.err == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, ErrInvalidClient)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

func TestFAPICIBAPlainCIBARegression(t *testing.T) {
	key := gen.MustRSAKey()
	serverKey := gen.MustRSAKey()

	t.Run("ShouldAcceptPushWithoutABindingMessage", func(t *testing.T) {
		_, provider, _ := newCIBATestProvider(serverKey, key)

		requester, err := sendCIBAFAPITestRequest(t, provider, cibaTestClientPush, func(form url.Values) {
			form.Set(consts.FormParameterClientNotificationToken, "token")
		})

		require.NoError(t, ErrorToDebugRFC6749Error(err))
		assert.Equal(t, consts.CIBAModePush, requester.GetDeliveryMode())
		assert.Empty(t, requester.GetBindingMessage())
	})

	t.Run("ShouldAcceptPollWithoutABindingMessageOrRequestContext", func(t *testing.T) {
		_, provider, _ := newCIBATestProvider(serverKey, key)

		requester, err := sendCIBAFAPITestRequest(t, provider, cibaTestClientPoll, nil)

		require.NoError(t, ErrorToDebugRFC6749Error(err))
		assert.Empty(t, requester.GetBindingMessage())
		assert.Empty(t, requester.GetRequestContext())
	})

	t.Run("ShouldDefaultTheSignedRequestMaximumLifetime", func(t *testing.T) {
		testCases := []struct {
			name     string
			config   *Config
			expected time.Duration
		}{
			{name: "ShouldUseTheConfiguredMaximum", config: &Config{CIBASignedRequestMaximumLifetime: 5 * time.Minute, RequestObjectMaximumLifetime: 30 * time.Minute}, expected: 5 * time.Minute},
			{name: "ShouldUseTheRequestObjectMaximum", config: &Config{RequestObjectMaximumLifetime: 30 * time.Minute}, expected: 30 * time.Minute},
			{name: "ShouldUseTheRequestObjectMaximumForANegativeMaximum", config: &Config{CIBASignedRequestMaximumLifetime: -1, RequestObjectMaximumLifetime: 30 * time.Minute}, expected: 30 * time.Minute},
			{name: "ShouldUseSixtyMinutesWhenTheRequestObjectMaximumIsDisabled", config: &Config{RequestObjectMaximumLifetime: -1}, expected: time.Hour},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.expected, tc.config.GetCIBASignedRequestMaximumLifetime(t.Context()))
			})
		}
	})

	t.Run("ShouldDefaultTheFAPICIBAOptionsOff", func(t *testing.T) {
		config := &Config{}

		assert.False(t, config.GetCIBARequireRequestContext(t.Context()))
		assert.Equal(t, time.Hour, config.GetCIBASignedRequestMaximumLifetime(t.Context()))
		assert.False(t, config.GetCIBARequireSingleAudienceAssertion(t.Context()))
		assert.Empty(t, config.GetCIBALoginHintTokenTypes(t.Context()))
		assert.Contains(t, config.GetCIBATokenDeliveryModes(t.Context()), consts.CIBAModePush)
	})
}

func sendCIBAFAPITestRequest(t *testing.T, provider *Fosite, client string, modify func(form url.Values)) (requester BackChannelAuthenticationRequester, err error) {
	t.Helper()

	form := url.Values{
		consts.FormParameterScope:     {consts.ScopeOpenID},
		consts.FormParameterLoginHint: {cibaTestSubject},
	}

	if modify != nil {
		modify(form)
	}

	r := newCIBATestRequest(t, nil, "", client, "", form.Encode())

	return provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})
}

func newCIBAFAPITestSignedClaims(name string, nbf, exp time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		jwt.ClaimIssuer:                    cibaSignedTestClientES256,
		jwt.ClaimAudience:                  cibaTestIssuer,
		jwt.ClaimExpirationTime:            exp.Unix(),
		jwt.ClaimIssuedAt:                  time.Now().Unix(),
		jwt.ClaimNotBefore:                 nbf.Unix(),
		jwt.ClaimJWTID:                     "jti-fapi-" + name,
		consts.FormParameterScope:          consts.ScopeOpenID,
		consts.FormParameterLoginHint:      cibaTestSubject,
		consts.FormParameterBindingMessage: cibaFAPITestBindingMessage,
		consts.FormParameterRequestContext: map[string]any{"geo": "x"},
	}
}

func sendCIBAFAPITestSignedRequest(t *testing.T, provider *Fosite, key any, claims jwt.MapClaims) (requester BackChannelAuthenticationRequester, err error) {
	t.Helper()

	form := url.Values{consts.FormParameterRequest: {mustGenerateClientAssertion(t, claims, jose.ES256, "", cibaTestKID, key)}}

	r := httptest.NewRequest(http.MethodPost, cibaTestURL, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(cibaSignedTestClientES256, cibaTestSecret)

	return provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})
}

func assertCIBAFAPITestError(t *testing.T, err error, expected *RFC6749Error, hint string) {
	t.Helper()

	require.Error(t, err)

	rfc, ok := errors.AsType[*RFC6749Error](err)
	require.True(t, ok)
	assert.Equal(t, expected.ErrorField, rfc.ErrorField, "%+v", ErrorToDebugRFC6749Error(err))

	if hint != "" {
		assert.Contains(t, rfc.HintField, hint, "%+v", ErrorToDebugRFC6749Error(err))
	}
}

func cibaFAPITestStores() map[string]func() (Storage, *storage.MemoryStore) {
	return map[string]func() (Storage, *storage.MemoryStore){
		cibaFAPITestStoreMemory: func() (Storage, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		},
		cibaFAPITestStoreHydrating: func() (Storage, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		},
	}
}

func TestBackChannelAuthenticationRejectsPublicClients(t *testing.T) {
	const client = "public-poll"

	for storeName, newStore := range cibaFAPITestStores() {
		t.Run(storeName, func(t *testing.T) {
			config, _, _ := newCIBATestProvider(gen.MustRSAKey(), gen.MustRSAKey())

			store, memory := newStore()
			memory.Clients[client] = &DefaultRegisteredClient{
				DefaultClient: &DefaultClient{
					ID:         client,
					Public:     true,
					GrantTypes: []string{consts.GrantTypeOpenIDCIBA},
					Scopes:     []string{consts.ScopeOpenID},
				},
				TokenEndpointAuthMethod:      consts.ClientAuthMethodNone,
				BackChannelTokenDeliveryMode: consts.CIBAModePoll,
			}

			provider := &Fosite{Store: store, Config: config}

			form := url.Values{
				consts.FormParameterClientID:  {client},
				consts.FormParameterScope:     {consts.ScopeOpenID},
				consts.FormParameterLoginHint: {cibaTestSubject},
			}

			r := httptest.NewRequest(http.MethodPost, cibaTestURL, strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			_, err := provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})

			assertCIBAFAPITestError(t, err, ErrInvalidClient, "")

			rfc, ok := errors.AsType[*RFC6749Error](err)
			require.True(t, ok)
			assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)
		})
	}
}

type uniqueContextTypeHandler struct {
	internal.PaymentInitiationTypeHandler

	unique bool
}

func (h *uniqueContextTypeHandler) IsUniqueAuthorizationContext(_ context.Context, _ Requester, _ AuthorizationDetail) bool {
	return h.unique
}
