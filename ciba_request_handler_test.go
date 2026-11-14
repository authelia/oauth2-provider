// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
	cibaTestIssuer = "https://as.example.com"
	cibaTestURL    = "https://as.example.com/ciba"
	cibaTestSecret = "0123456789abcdef0123456789abcdef"
	cibaTestKID    = "ciba-kid"

	cibaTestClientPoll           = "poll"
	cibaTestClientPing           = "ping"
	cibaTestClientPush           = "push"
	cibaTestClientNoMode         = "no-mode"
	cibaTestClientUserCode       = "user-code"
	cibaTestClientSigned         = "signed"
	cibaTestClientPairwiseBasic  = "pairwise-basic"
	cibaTestClientPairwisePKJWT  = "pairwise-pkjwt"
	cibaTestClientOther          = "other"
	cibaTestNotificationEndpoint = "https://client.example.com/cb"

	cibaTestClientPollNoGrant    = "poll-no-grant"
	cibaTestClientPingNoGrant    = "ping-no-grant"
	cibaTestClientPushNoGrant    = "push-no-grant"
	cibaTestClientPingHTTP       = "ping-http"
	cibaTestClientPushNoEndpoint = "push-no-endpoint"
	cibaTestClientIDTEncRSA15    = "id-token-rsa1_5"
	cibaTestClientATRSA15        = "access-token-rsa1_5"
)

func TestNewBackChannelAuthenticationRequest(t *testing.T) {
	testCases := []struct {
		name   string
		client string
		method string
		config func(config *Config)
		form   func(form url.Values)
		raw    string
		secret string
		err    *RFC6749Error
		hint   string
		check  func(t *testing.T, requester BackChannelAuthenticationRequester)
	}{
		{
			name:   "ShouldRejectGET",
			method: http.MethodGet,
			err:    ErrInvalidRequest,
		},
		{
			name: "ShouldRejectARepeatedLoginHint",
			raw:  "scope=openid&login_hint=alice&login_hint=bob",
			err:  ErrInvalidRequest,
			hint: "The 'login_hint' parameter must not be included more than once.",
		},
		{
			name: "ShouldRejectARepeatedClientID",
			raw:  "scope=openid&login_hint=alice&client_id=poll&client_id=poll",
			err:  ErrInvalidRequest,
			hint: "The 'client_id' parameter must not be included more than once.",
		},
		{
			name: "ShouldRejectARepeatedAuthorizationDetails",
			raw:  "scope=openid&login_hint=alice&authorization_details=%5B%5D&authorization_details=%5B%5D",
			err:  ErrInvalidRequest,
			hint: "The 'authorization_details' parameter must not be included more than once.",
		},
		{
			name: "ShouldRejectARepeatedDPoPJKT",
			raw:  "scope=openid&login_hint=alice&dpop_jkt=abc&dpop_jkt=abc",
			err:  ErrInvalidRequest,
			hint: "The 'dpop_jkt' parameter must not be included more than once.",
		},
		{
			name: "ShouldRejectARepeatedScope",
			raw:  "scope=openid&scope=profile&login_hint=alice",
			err:  ErrInvalidRequest,
			hint: "The 'scope' parameter must not be included more than once.",
		},
		{
			name:   "ShouldRejectAnUnauthenticatedClient",
			secret: "wrong",
			err:    ErrInvalidClient,
		},
		{
			name:   "ShouldRejectAClientWithoutADeliveryMode",
			client: cibaTestClientNoMode,
			err:    ErrUnauthorizedClient,
			hint:   "token delivery mode",
		},
		{
			name:   "ShouldRejectADeliveryModeTheServerDoesNotSupport",
			config: func(config *Config) { config.CIBATokenDeliveryModes = []string{consts.CIBAModePing} },
			err:    ErrUnauthorizedClient,
		},
		{
			name:   "ShouldRejectAPollClientWithoutTheCIBAGrantType",
			client: cibaTestClientPollNoGrant,
			err:    ErrUnauthorizedClient,
			hint:   "'urn:openid:params:grant-type:ciba' grant type",
		},
		{
			name:   "ShouldRejectAPingClientWithoutTheCIBAGrantType",
			client: cibaTestClientPingNoGrant,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "token") },
			err:    ErrUnauthorizedClient,
			hint:   "'urn:openid:params:grant-type:ciba' grant type",
		},
		{
			name:   "ShouldAcceptAPushClientWithoutTheCIBAGrantType",
			client: cibaTestClientPushNoGrant,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "token") },
		},
		{
			name:   "ShouldRejectAPingClientWithAnHTTPNotificationEndpoint",
			client: cibaTestClientPingHTTP,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "token") },
			err:    ErrUnauthorizedClient,
			hint:   "'backchannel_client_notification_endpoint'",
		},
		{
			name:   "ShouldRejectAPushClientWithoutANotificationEndpoint",
			client: cibaTestClientPushNoEndpoint,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "token") },
			err:    ErrUnauthorizedClient,
			hint:   "'backchannel_client_notification_endpoint'",
		},
		{
			name: "ShouldRejectAClientAssertionEncryptedWithRSA15",
			form: func(form url.Values) {
				form.Set(consts.FormParameterClientAssertionType, consts.ClientAssertionTypeJWTBearer)
				form.Set(consts.FormParameterClientAssertion, mustCIBATestJWE(jose.RSA1_5))
			},
			err:  ErrInvalidClient,
			hint: "must not be encrypted with the 'RSA1_5' key management algorithm",
		},
		{
			name:   "ShouldRejectAClientEncryptingIDTokensWithRSA15",
			client: cibaTestClientIDTEncRSA15,
			err:    ErrUnauthorizedClient,
			hint:   "'id_token_encrypted_response_alg'",
		},
		{
			name:   "ShouldRejectAClientEncryptingAccessTokensWithRSA15",
			client: cibaTestClientATRSA15,
			err:    ErrUnauthorizedClient,
			hint:   "'access_token_encrypted_response_alg'",
		},
		{
			name:   "ShouldRejectAPairwisePollClientUsingClientSecretBasic",
			client: cibaTestClientPairwiseBasic,
			err:    ErrInvalidClient,
			hint:   "A pairwise OAuth 2.0 Client",
		},
		{
			name:   "ShouldAcceptAPairwisePollClientUsingPrivateKeyJWT",
			client: cibaTestClientPairwisePKJWT,
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, cibaTestClientPairwisePKJWT, requester.GetClient().GetID())
				assert.Empty(t, requester.GetRequestForm().Get(consts.FormParameterClientAssertion))
			},
		},
		{
			name:   "ShouldRejectAnUnsignedRequestFromAClientRegisteredForSignedRequests",
			client: cibaTestClientSigned,
			err:    ErrInvalidRequest,
			hint:   "must send a signed authentication request",
		},
		{
			name: "ShouldRejectASignedRequestFromAClientNotRegisteredForSignedRequests",
			form: func(form url.Values) { form.Set(consts.FormParameterRequest, "a.b.c") },
			err:  ErrInvalidRequest,
			hint: "must register the 'backchannel_authentication_request_signing_alg'",
		},
		{
			name: "ShouldRejectAMissingScope",
			form: func(form url.Values) { form.Del(consts.FormParameterScope) },
			err:  ErrInvalidRequest,
			hint: "The 'scope' parameter is required.",
		},
		{
			name: "ShouldRejectAMissingOpenIDScope",
			form: func(form url.Values) { form.Set(consts.FormParameterScope, "profile") },
			err:  ErrInvalidRequest,
			hint: "'openid' scope",
		},
		{
			name:   "ShouldRejectAPushClientWithoutOpenIDWhenTheRequirementIsDisabled",
			client: cibaTestClientPush,
			config: func(config *Config) { config.CIBADisableOpenIDScopeRequirement = true },
			form: func(form url.Values) {
				form.Set(consts.FormParameterScope, "profile")
				form.Set(consts.FormParameterClientNotificationToken, "token")
			},
			err:  ErrInvalidRequest,
			hint: "'openid' scope",
		},
		{
			name:   "ShouldAcceptAPollClientWithoutOpenIDWhenTheRequirementIsDisabled",
			config: func(config *Config) { config.CIBADisableOpenIDScopeRequirement = true },
			form:   func(form url.Values) { form.Set(consts.FormParameterScope, "profile") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, Arguments{"profile"}, requester.GetRequestedScopes())
			},
		},
		{
			name: "ShouldRejectAScopeTheClientMayNotRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterScope, "openid admin") },
			err:  ErrInvalidScope,
		},
		{
			name: "ShouldRejectNoHint",
			form: func(form url.Values) { form.Del(consts.FormParameterLoginHint) },
			err:  ErrInvalidRequest,
			hint: "Exactly one of",
		},
		{
			name: "ShouldRejectTwoHints",
			form: func(form url.Values) { form.Set(consts.FormParameterLoginHintToken, "token") },
			err:  ErrInvalidRequest,
			hint: "Exactly one of",
		},
		{
			name: "ShouldAcceptALoginHintToken",
			form: func(form url.Values) {
				form.Del(consts.FormParameterLoginHint)
				form.Set(consts.FormParameterLoginHintToken, "opaque")
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				kind, value := requester.GetHint()
				assert.Equal(t, CIBAHintKindLoginHintToken, kind)
				assert.Equal(t, "opaque", value)
				assert.Nil(t, requester.GetIDTokenHintClaims())
			},
		},
		{
			name: "ShouldRejectAnInvalidIDTokenHint",
			form: func(form url.Values) {
				form.Del(consts.FormParameterLoginHint)
				form.Set(consts.FormParameterIDTokenHint, "not-a-jwt")
			},
			err:  ErrInvalidRequest,
			hint: "'id_token_hint'",
		},
		{
			name:   "ShouldRejectAPingClientWithoutANotificationToken",
			client: cibaTestClientPing,
			err:    ErrInvalidRequest,
			hint:   "'client_notification_token' parameter is required",
		},
		{
			name:   "ShouldRejectAPushClientWithoutANotificationToken",
			client: cibaTestClientPush,
			err:    ErrInvalidRequest,
			hint:   "'client_notification_token' parameter is required",
		},
		{
			name:   "ShouldRejectANotificationTokenLongerThan1024Characters",
			client: cibaTestClientPing,
			form: func(form url.Values) {
				form.Set(consts.FormParameterClientNotificationToken, strings.Repeat("a", 1025))
			},
			err:  ErrInvalidRequest,
			hint: "must not exceed 1024",
		},
		{
			name:   "ShouldRejectANotificationTokenWithASpace",
			client: cibaTestClientPing,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "abc def") },
			err:    ErrInvalidRequest,
			hint:   "b64token",
		},
		{
			name:   "ShouldRejectANotificationTokenWithPaddingInTheMiddle",
			client: cibaTestClientPing,
			form:   func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "ab=cd") },
			err:    ErrInvalidRequest,
			hint:   "b64token",
		},
		{
			name:   "ShouldAcceptAPingClientWithA1024CharacterNotificationToken",
			client: cibaTestClientPing,
			form: func(form url.Values) {
				form.Set(consts.FormParameterClientNotificationToken, strings.Repeat("a", 1022)+"==")
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, consts.CIBAModePing, requester.GetDeliveryMode())
				assert.Equal(t, strings.Repeat("a", 1022)+"==", GetClientNotificationToken(requester))
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterClientNotificationToken))
			},
		},
		{
			name: "ShouldAcceptAPollClientWithoutANotificationToken",
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, consts.CIBAModePoll, requester.GetDeliveryMode())
				assert.Empty(t, GetClientNotificationToken(requester))
			},
		},
		{
			name: "ShouldIgnoreANotificationTokenFromAPollClient",
			form: func(form url.Values) { form.Set(consts.FormParameterClientNotificationToken, "abc def") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Empty(t, GetClientNotificationToken(requester))
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterClientNotificationToken))
			},
		},
		{
			name: "ShouldRejectA65CharacterBindingMessage",
			form: func(form url.Values) { form.Set(consts.FormParameterBindingMessage, strings.Repeat("a", 65)) },
			err:  ErrInvalidBindingMessage,
			hint: "must not exceed 64",
		},
		{
			name: "ShouldRejectABindingMessageWithANewline",
			form: func(form url.Values) { form.Set(consts.FormParameterBindingMessage, "abc\ndef") },
			err:  ErrInvalidBindingMessage,
			hint: "printable",
		},
		{
			name: "ShouldAcceptA64CharacterMultibyteBindingMessage",
			form: func(form url.Values) { form.Set(consts.FormParameterBindingMessage, strings.Repeat("é", 64)) },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, strings.Repeat("é", 64), requester.GetBindingMessage())
			},
		},
		{
			name:   "ShouldRejectAMissingBindingMessageWhenRequired",
			config: func(config *Config) { config.CIBARequireBindingMessage = true },
			err:    ErrInvalidRequest,
			hint:   "'binding_message' parameter is required",
		},
		{
			name: "ShouldDropAUserCodeWhenTheServerDoesNotSupportIt",
			form: func(form url.Values) { form.Set(consts.FormParameterUserCode, "1234") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, "", requester.GetUserCode())
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterUserCode))
			},
		},
		{
			name:   "ShouldDropAUserCodeWhenTheClientDoesNotSupportIt",
			config: func(config *Config) { config.CIBAUserCodeSupported = true },
			form:   func(form url.Values) { form.Set(consts.FormParameterUserCode, "1234") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, "", requester.GetUserCode())
			},
		},
		{
			name:   "ShouldKeepAUserCodeWhenTheServerAndClientSupportIt",
			client: cibaTestClientUserCode,
			config: func(config *Config) { config.CIBAUserCodeSupported = true },
			form:   func(form url.Values) { form.Set(consts.FormParameterUserCode, "1234") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, "1234", requester.GetUserCode())
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterUserCode))
			},
		},
		{
			name: "ShouldRejectARequestedExpiryOfZero",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "0") },
			err:  ErrInvalidRequest,
			hint: "'requested_expiry'",
		},
		{
			name: "ShouldRejectANonNumericRequestedExpiry",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "abc") },
			err:  ErrInvalidRequest,
			hint: "'requested_expiry'",
		},
		{
			name: "ShouldRejectASignedRequestedExpiry",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "+120") },
			err:  ErrInvalidRequest,
			hint: "'requested_expiry'",
		},
		{
			name: "ShouldKeepAnOverflowingRequestedExpiryAsTheMaximum",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "99999999999999999999") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, time.Duration(math.MaxInt64/int64(time.Second))*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name: "ShouldKeepARequestedExpiryAboveTheDurationRangeAsTheMaximum",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "9223372037") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, time.Duration(math.MaxInt64/int64(time.Second))*time.Second, requester.GetRequestedExpiry())
			},
		},
		{
			name: "ShouldKeepTheRequestedExpiryUnclamped",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestedExpiry, "86400") },
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, 24*time.Hour, requester.GetRequestedExpiry())
			},
		},
		{
			name: "ShouldKeepTheACRValuesInTheForm",
			form: func(form url.Values) {
				form.Set(consts.FormParameterAuthenticationContextClassReferenceValues, "urn:example:loa:2")
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, "urn:example:loa:2", requester.GetRequestForm().Get(consts.FormParameterAuthenticationContextClassReferenceValues))
			},
		},
		{
			name: "ShouldRejectAnAudienceTheClientMayNotRequest",
			form: func(form url.Values) { form.Set(consts.FormParameterAudience, "https://elsewhere.example.com") },
			err:  ErrInvalidTarget,
		},
		{
			name: "ShouldRejectARelativeResourceIndicator",
			form: func(form url.Values) { form.Set(consts.FormParameterResource, "relative") },
			err:  ErrInvalidTarget,
		},
		{
			name: "ShouldRejectMalformedAuthorizationDetails",
			config: func(config *Config) {
				config.AuthorizationDetailsTypeHandlers = newRARConfig().AuthorizationDetailsTypeHandlers
			},
			form: func(form url.Values) { form.Set(consts.FormParameterAuthorizationDetails, "{") },
			err:  ErrInvalidAuthorizationDetails,
		},
		{
			name: "ShouldRejectALowEntropyNonce",
			form: func(form url.Values) { form.Set(consts.FormParameterNonce, "abc") },
			err:  ErrInsufficientEntropy,
		},
		{
			name: "ShouldRejectARequestContextWhichIsNotAJSONObject",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestContext, "[1]") },
			err:  ErrInvalidRequest,
			hint: "'request_context'",
		},
		{
			name: "ShouldRejectARequestContextWhichIsNotJSON",
			form: func(form url.Values) { form.Set(consts.FormParameterRequestContext, "{") },
			err:  ErrInvalidRequest,
			hint: "'request_context'",
		},
		{
			name: "ShouldIgnoreAnUnrecognisedParameter",
			form: func(form url.Values) { form.Set("foo", "bar") },
		},
		{
			name: "ShouldDropThePromptAndMaxAgeParameters",
			form: func(form url.Values) {
				form.Set(consts.FormParameterPrompt, consts.PromptTypeNone)
				form.Set(consts.FormParameterMaximumAge, "0")
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterPrompt))
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterMaximumAge))
			},
		},
		{
			name: "ShouldAcceptAFullRequest",
			form: func(form url.Values) {
				form.Set(consts.FormParameterScope, "openid profile")
				form.Set(consts.FormParameterBindingMessage, "W4SCT")
				form.Set(consts.FormParameterRequestedExpiry, "120")
				form.Set(consts.FormParameterRequestContext, `{"a":1}`)
			},
			check: func(t *testing.T, requester BackChannelAuthenticationRequester) {
				assert.Equal(t, cibaTestClientPoll, requester.GetClient().GetID())
				assert.Equal(t, consts.CIBAModePoll, requester.GetDeliveryMode())
				assert.Equal(t, Arguments{"openid", "profile"}, requester.GetRequestedScopes())

				kind, value := requester.GetHint()
				assert.Equal(t, CIBAHintKindLoginHint, kind)
				assert.Equal(t, "alice", value)

				assert.Equal(t, "W4SCT", requester.GetBindingMessage())
				assert.Equal(t, 120*time.Second, requester.GetRequestedExpiry())
				assert.JSONEq(t, `{"a":1}`, string(requester.GetRequestContext()))
				assert.NotNil(t, requester.GetSession())
				assert.Equal(t, CIBAStatusPending, requester.GetStatus())
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterClientID))
				assert.False(t, requester.GetRequestForm().Has(consts.FormParameterClientSecret))
			},
		},
	}

	key := gen.MustRSAKey()
	serverKey := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, _ := newCIBATestProvider(serverKey, key)

			if tc.config != nil {
				tc.config(config)
			}

			client := tc.client
			if client == "" {
				client = cibaTestClientPoll
			}

			form := url.Values{
				consts.FormParameterScope:     {"openid"},
				consts.FormParameterLoginHint: {"alice"},
			}

			if tc.form != nil {
				tc.form(form)
			}

			body := form.Encode()
			if tc.raw != "" {
				body = tc.raw
			}

			r := newCIBATestRequest(t, key, tc.method, client, tc.secret, body)

			session := &DefaultSession{}

			requester, err := provider.NewBackChannelAuthenticationRequest(t.Context(), r, session)

			if tc.err != nil {
				require.Error(t, err)

				rfc, ok := errors.AsType[*RFC6749Error](err)
				require.True(t, ok)
				assert.Equal(t, tc.err.ErrorField, rfc.ErrorField, "%+v", ErrorToDebugRFC6749Error(err))
				assert.Equal(t, tc.err.CodeField, rfc.CodeField)

				if tc.hint != "" {
					assert.Contains(t, rfc.HintField, tc.hint)
				}

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, requester)
			assert.Equal(t, session, requester.GetSession())

			if tc.check != nil {
				tc.check(t, requester)
			}
		})
	}
}

func TestBackChannelAuthenticationEndpointAuthMethodErrorNamesTokenEndpointAuthMethod(t *testing.T) {
	key := gen.MustRSAKey()
	_, provider, _ := newCIBATestProvider(gen.MustRSAKey(), key)

	r := httptest.NewRequest(http.MethodPost, cibaTestURL, strings.NewReader(url.Values{
		consts.FormParameterScope:     {"openid"},
		consts.FormParameterLoginHint: {"alice"},
	}.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(cibaTestClientPairwisePKJWT, cibaTestSecret)

	_, err := provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})

	require.ErrorIs(t, err, ErrInvalidClient)

	debug := ErrorToDebugRFC6749Error(err).Error()

	assert.Contains(t, debug, "'token_endpoint_auth_method' method 'client_secret_basic'")
	assert.NotContains(t, debug, "backchannel_authentication_endpoint_auth_method")
}

// cibaZeroIDTokenHintAgeConfig is a configuration whose 'id_token_hint' grace period is zero.
type cibaZeroIDTokenHintAgeConfig struct {
	*Config
}

func (c *cibaZeroIDTokenHintAgeConfig) GetCIBAIDTokenHintMaximumAge(_ context.Context) time.Duration {
	return 0
}

func TestBackChannelIDTokenHint(t *testing.T) {
	testCases := []struct {
		name    string
		claims  func(claims jwt.MapClaims)
		tamper  bool
		zeroAge bool
		err     *RFC6749Error
	}{
		{
			name: "ShouldAcceptATokenExpiredOneHourAgo",
		},
		{
			name: "ShouldRejectATokenExpired25HoursAgo",
			claims: func(claims jwt.MapClaims) {
				claims[jwt.ClaimIssuedAt] = jwt.NewNumericDate(time.Now().Add(-26 * time.Hour))
				claims[jwt.ClaimExpirationTime] = jwt.NewNumericDate(time.Now().Add(-25 * time.Hour))
			},
			err: ErrInvalidRequest,
		},
		{
			name: "ShouldRejectATokenExpired25HoursAgoWhenTheConfiguredGracePeriodIsZero",
			claims: func(claims jwt.MapClaims) {
				claims[jwt.ClaimIssuedAt] = jwt.NewNumericDate(time.Now().Add(-26 * time.Hour))
				claims[jwt.ClaimExpirationTime] = jwt.NewNumericDate(time.Now().Add(-25 * time.Hour))
			},
			zeroAge: true,
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldAcceptATokenExpiredOneHourAgoWhenTheConfiguredGracePeriodIsZero",
			zeroAge: true,
		},
		{
			name:   "ShouldRejectATokenIssuedToAnotherClient",
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimAudience] = []string{cibaTestClientOther} },
			err:    ErrInvalidRequest,
		},
		{
			name:   "ShouldRejectATokenAuthorizedForAnotherClient",
			claims: func(claims jwt.MapClaims) { claims[consts.ClaimAuthorizedParty] = cibaTestClientOther },
			err:    ErrInvalidRequest,
		},
		{
			name:   "ShouldRejectATokenFromAnotherIssuer",
			claims: func(claims jwt.MapClaims) { claims[jwt.ClaimIssuer] = "https://evil.example.com" },
			err:    ErrInvalidRequest,
		},
		{
			name:   "ShouldRejectATamperedSignature",
			tamper: true,
			err:    ErrInvalidRequest,
		},
	}

	key := gen.MustRSAKey()
	serverKey := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, strategy := newCIBATestProvider(serverKey, key)

			if tc.zeroAge {
				provider.Config = &cibaZeroIDTokenHintAgeConfig{Config: config}
			}

			claims := jwt.MapClaims{
				jwt.ClaimIssuer:         cibaTestIssuer,
				jwt.ClaimSubject:        "alice",
				jwt.ClaimAudience:       []string{cibaTestClientPoll},
				jwt.ClaimIssuedAt:       jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				jwt.ClaimExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			}

			if tc.claims != nil {
				tc.claims(claims)
			}

			hint, _, err := strategy.Encode(t.Context(), claims)
			require.NoError(t, err)

			if tc.tamper {
				segments := strings.SplitN(hint, ".", 3)
				require.Len(t, segments, 3)

				signature := []byte(segments[2])
				if signature[0] == 'A' {
					signature[0] = 'B'
				} else {
					signature[0] = 'A'
				}

				hint = strings.Join([]string{segments[0], segments[1], string(signature)}, ".")
			}

			r := newCIBATestRequest(t, key, "", cibaTestClientPoll, "", url.Values{
				consts.FormParameterScope:       {"openid"},
				consts.FormParameterIDTokenHint: {hint},
			}.Encode())

			requester, err := provider.NewBackChannelAuthenticationRequest(t.Context(), r, &DefaultSession{})

			if tc.err != nil {
				require.Error(t, err)

				rfc, ok := errors.AsType[*RFC6749Error](err)
				require.True(t, ok)
				assert.Equal(t, tc.err.ErrorField, rfc.ErrorField, "%+v", ErrorToDebugRFC6749Error(err))

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))

			kind, value := requester.GetHint()
			assert.Equal(t, CIBAHintKindIDTokenHint, kind)
			assert.Equal(t, hint, value)
			assert.Equal(t, "alice", requester.GetIDTokenHintClaims()[jwt.ClaimSubject])
		})
	}
}

func newCIBATestProvider(serverKey, clientKey *rsa.PrivateKey) (config *Config, provider *Fosite, strategy jwt.Strategy) {
	config = &Config{
		Issuer:              cibaTestIssuer,
		JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
		MinParameterEntropy: 8,
		EndpointURLs:        EndpointURLs{BackChannelAuthentication: cibaTestURL},
	}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(serverKey)}

	config.JWTStrategy = jwtStrategy
	config.IDTokenValidationStrategy = &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	store := storage.NewMemoryStore()

	newClient := func(id, mode string) *DefaultRegisteredClient {
		c := &DefaultRegisteredClient{
			DefaultClient: &DefaultClient{
				ID:           id,
				ClientSecret: NewPlainTextClientSecret(cibaTestSecret),
				GrantTypes:   []string{consts.GrantTypeOpenIDCIBA},
				Scopes:       []string{"openid", "profile"},
			},
			TokenEndpointAuthMethod:      consts.ClientAuthMethodClientSecretBasic,
			BackChannelTokenDeliveryMode: mode,
		}

		if mode == consts.CIBAModePing || mode == consts.CIBAModePush {
			c.BackChannelClientNotificationEndpoint = cibaTestNotificationEndpoint
		}

		store.Clients[id] = c

		return c
	}

	newClient(cibaTestClientPoll, consts.CIBAModePoll)
	newClient(cibaTestClientPing, consts.CIBAModePing)
	newClient(cibaTestClientPush, consts.CIBAModePush)
	newClient(cibaTestClientNoMode, "")
	newClient(cibaTestClientOther, consts.CIBAModePoll)
	newClient(cibaTestClientUserCode, consts.CIBAModePoll).BackChannelUserCodeParameter = true
	newClient(cibaTestClientSigned, consts.CIBAModePoll).BackChannelAuthenticationRequestSigningAlg = string(jose.PS256)
	newClient(cibaTestClientPollNoGrant, consts.CIBAModePoll).GrantTypes = nil
	newClient(cibaTestClientPingNoGrant, consts.CIBAModePing).GrantTypes = nil
	newClient(cibaTestClientPushNoGrant, consts.CIBAModePush).GrantTypes = nil
	newClient(cibaTestClientPingHTTP, consts.CIBAModePing).BackChannelClientNotificationEndpoint = "http://client.example.com/cb"
	newClient(cibaTestClientPushNoEndpoint, consts.CIBAModePush).BackChannelClientNotificationEndpoint = ""
	newClient(cibaTestClientIDTEncRSA15, consts.CIBAModePoll).IDTokenEncryptedResponseAlg = string(jose.RSA1_5)
	newClient(cibaTestClientATRSA15, consts.CIBAModePoll).AccessTokenEncryptedResponseAlg = string(jose.RSA1_5)

	pairwiseBasic := newClient(cibaTestClientPairwiseBasic, consts.CIBAModePoll)
	pairwiseBasic.SubjectType = consts.SubjectTypePairwise
	pairwiseBasic.JSONWebKeysURI = "https://client.example.com/jwks"

	pairwisePKJWT := newClient(cibaTestClientPairwisePKJWT, consts.CIBAModePoll)
	pairwisePKJWT.SubjectType = consts.SubjectTypePairwise
	pairwisePKJWT.TokenEndpointAuthMethod = consts.ClientAuthMethodPrivateKeyJWT
	pairwisePKJWT.JSONWebKeys = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: cibaTestKID, Use: "sig", Algorithm: "RS256", Key: &clientKey.PublicKey}},
	}

	return config, &Fosite{Store: store, Config: config}, jwtStrategy
}

func newCIBATestRequest(t *testing.T, key *rsa.PrivateKey, method, client, secret, body string) *http.Request {
	t.Helper()

	if method == "" {
		method = http.MethodPost
	}

	if client == cibaTestClientPairwisePKJWT {
		values, err := url.ParseQuery(body)
		require.NoError(t, err)

		values.Set(consts.FormParameterClientAssertionType, consts.ClientAssertionTypeJWTBearer)
		values.Set(consts.FormParameterClientAssertion, mustGenerateClientAssertion(t, jwt.MapClaims{
			consts.ClaimSubject:        client,
			consts.ClaimIssuer:         client,
			consts.ClaimAudience:       cibaTestIssuer,
			consts.ClaimJWTID:          strconv.FormatInt(time.Now().UnixNano(), 10),
			consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, cibaTestKID, key))

		body = values.Encode()
	}

	r := httptest.NewRequest(method, cibaTestURL, strings.NewReader(body))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if client != cibaTestClientPairwisePKJWT {
		if secret == "" {
			secret = cibaTestSecret
		}

		r.SetBasicAuth(client, secret)
	}

	return r
}

func mustCIBATestJWE(alg jose.KeyAlgorithm) string {
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: alg, Key: &gen.MustRSAKey().PublicKey}, (&jose.EncrypterOptions{}).WithContentType(jwt.JSONWebTokenTypeJWT))
	if err != nil {
		panic(err)
	}

	object, err := encrypter.Encrypt([]byte("a.b.c"))
	if err != nil {
		panic(err)
	}

	assertion, err := object.CompactSerialize()
	if err != nil {
		panic(err)
	}

	return assertion
}
