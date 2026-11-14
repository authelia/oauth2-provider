// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

type cibaGrantHandler struct {
	oauth2.TokenEndpointHandler
}

func (cibaGrantHandler) GrantTypesSupported(_ context.Context) []string {
	return []string{consts.GrantTypeOpenIDCIBA}
}

func newCIBAConfig(config *oauth2.Config) *oauth2.Config {
	config.TokenEndpointHandlers.Append(cibaGrantHandler{})

	return withTestCapabilities(config)
}

func TestValidateCIBARegistration(t *testing.T) {
	const prefix = "The value of one of the client metadata fields is invalid and the server has rejected this request. "

	const sector = "https://example.com/sector"

	cibaGrant := []string{consts.GrantTypeOpenIDCIBA}

	valid := func(mutate func(m *oauth2.ClientRegistrationMetadata)) *oauth2.ClientRegistrationMetadata {
		m := &oauth2.ClientRegistrationMetadata{
			GrantTypes:                   cibaGrant,
			BackChannelTokenDeliveryMode: consts.CIBAModePoll,
			TokenEndpointAuthMethod:      consts.ClientAuthMethodClientSecretBasic,
		}

		mutate(m)

		return m
	}

	testCases := []struct {
		name     string
		config   *oauth2.Config
		metadata *oauth2.ClientRegistrationMetadata
		expected string
	}{
		{"ShouldAcceptPlainClient", &oauth2.Config{}, &oauth2.ClientRegistrationMetadata{RedirectURIs: []string{"https://example.com/cb"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}}, ""},
		{"ShouldAcceptPoll", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {}), ""},
		{"ShouldAcceptPing", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePing, "https://example.com/notify"
		}), ""},
		{"ShouldAcceptPush", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePush, "https://example.com/notify"
		}), ""},
		{"ShouldAcceptPushWithoutGrant", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.GrantTypes, m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = []string{"authorization_code"}, consts.CIBAModePush, "https://example.com/notify"
			m.RedirectURIs = []string{"https://example.com/cb"}
		}), ""},
		{"ShouldAcceptSignedRequestAlg", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelAuthenticationRequestSigningAlg = "RS256" }), ""},
		{"ShouldAcceptUserCodeWhenSupported", &oauth2.Config{CIBAUserCodeSupported: true}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelUserCodeParameter = true }), ""},
		{"ShouldAcceptPairwisePollWithJWKSURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.SubjectType, m.JSONWebKeysURI = consts.SubjectTypePairwise, "https://example.com/jwks"
		}), ""},
		{"ShouldRejectUnknownMode", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelTokenDeliveryMode = "fax" }), prefix + "The 'backchannel_token_delivery_mode' value 'fax' is not supported by this authorization server."},
		{"ShouldRejectModeNotEnabled", &oauth2.Config{CIBATokenDeliveryModes: []string{consts.CIBAModePoll}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePush, "https://example.com/notify"
		}), prefix + "The 'backchannel_token_delivery_mode' value 'push' is not supported by this authorization server."},
		{"ShouldRejectPollWithoutGrant", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.GrantTypes = []string{"client_credentials"} }), prefix + "The 'backchannel_token_delivery_mode' value 'poll' requires the 'grant_types' to include 'urn:openid:params:grant-type:ciba'."},
		{"ShouldRejectGrantWithoutMode", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelTokenDeliveryMode = "" }), prefix + "The 'grant_types' value 'urn:openid:params:grant-type:ciba' requires the 'backchannel_token_delivery_mode' to be registered."},
		{"ShouldRejectPingWithoutEndpoint", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelTokenDeliveryMode = consts.CIBAModePing }), prefix + "The 'backchannel_token_delivery_mode' value 'ping' requires the 'backchannel_client_notification_endpoint' to be registered."},
		{"ShouldRejectPushWithoutEndpoint", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelTokenDeliveryMode = consts.CIBAModePush }), prefix + "The 'backchannel_token_delivery_mode' value 'push' requires the 'backchannel_client_notification_endpoint' to be registered."},
		{"ShouldRejectHTTPEndpoint", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePing, "http://example.com/notify"
		}), prefix + "The 'backchannel_client_notification_endpoint' value 'http://example.com/notify' must use the 'https' scheme."},
		{"ShouldRejectEndpointFragment", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePing, "https://example.com/notify#frag"
		}), prefix + "The 'backchannel_client_notification_endpoint' value 'https://example.com/notify#frag' must not contain a fragment component."},
		{"ShouldRejectHS256", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelAuthenticationRequestSigningAlg = "HS256" }), prefix + "The 'backchannel_authentication_request_signing_alg' value 'HS256' must be an asymmetric signing algorithm."},
		{"ShouldRejectNoneAlg", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelAuthenticationRequestSigningAlg = "none" }), prefix + "The 'backchannel_authentication_request_signing_alg' value 'none' must be an asymmetric signing algorithm."},
		{"ShouldRejectAlgNotSupported", &oauth2.Config{CIBARequestSigningAlgValues: []string{"RS256"}}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelAuthenticationRequestSigningAlg = "ES256" }), prefix + "The 'backchannel_authentication_request_signing_alg' value 'ES256' is not supported by this authorization server."},
		{"ShouldAcceptUserCodeWhenUnsupported", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelUserCodeParameter = true }), ""},
		{"ShouldRejectPublicClient", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.TokenEndpointAuthMethod = consts.ClientAuthMethodNone }), prefix + "The 'token_endpoint_auth_method' value 'none' is not permitted with the 'backchannel_token_delivery_mode' as the backchannel authentication endpoint requires client authentication."},
		{"ShouldRejectRSA15IDTokenEncryption", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.IDTokenEncryptedResponseAlg, m.JSONWebKeysURI = string(jose.RSA1_5), "https://example.com/jwks"
		}), prefix + "The 'id_token_encrypted_response_alg' value 'RSA1_5' is not permitted with the 'backchannel_token_delivery_mode'."},
		{"ShouldRejectRSA15IDTokenEncryptionPush", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePush, "https://example.com/notify"
			m.IDTokenEncryptedResponseAlg, m.JSONWebKeysURI = string(jose.RSA1_5), "https://example.com/jwks"
		}), prefix + "The 'id_token_encrypted_response_alg' value 'RSA1_5' is not permitted with the 'backchannel_token_delivery_mode'."},
		{"ShouldAcceptRSAOAEPIDTokenEncryption", &oauth2.Config{}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.IDTokenEncryptedResponseAlg, m.JSONWebKeysURI = policyTestAlgRSAOAEP256, "https://example.com/jwks"
		}), ""},
		{"ShouldRejectPairwisePollWithoutJWKSURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) { m.SubjectType = consts.SubjectTypePairwise }), prefix + "The 'subject_type' value 'pairwise' with the 'backchannel_token_delivery_mode' value 'poll' requires the 'jwks_uri' to be registered."},
		{"ShouldRejectPairwisePingWithOnlySectorIdentifierURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePing, "https://example.com/notify"
			m.SubjectType, m.SectorIdentifierURI = consts.SubjectTypePairwise, sector
		}), prefix + "The 'subject_type' value 'pairwise' with the 'backchannel_token_delivery_mode' value 'ping' requires the 'jwks_uri' to be registered."},
		{"ShouldRejectPairwisePollWithOnlyInlineJWKS", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.SubjectType, m.JSONWebKeys = consts.SubjectTypePairwise, &jose.JSONWebKeySet{}
		}), prefix + "The 'subject_type' value 'pairwise' with the 'backchannel_token_delivery_mode' value 'poll' requires the 'jwks_uri' to be registered."},
		{"ShouldAcceptPairwisePollWithSectorIdentifierURIAndJWKSURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.SubjectType, m.SectorIdentifierURI, m.JSONWebKeysURI = consts.SubjectTypePairwise, sector, "https://example.com/jwks"
		}), ""},
		{"ShouldRejectPairwisePollWithHTTPJWKSURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.SubjectType, m.JSONWebKeysURI = consts.SubjectTypePairwise, "http://example.com/jwks"
		}), prefix + "The 'jwks_uri' value 'http://example.com/jwks' must use the 'https' scheme."},
		{"ShouldAcceptPairwisePushWithoutJWKSURI", &oauth2.Config{SubjectTypesSupported: []string{"public", "pairwise"}}, valid(func(m *oauth2.ClientRegistrationMetadata) {
			m.BackChannelTokenDeliveryMode, m.BackChannelClientNotificationEndpoint = consts.CIBAModePush, "https://example.com/notify"
			m.SubjectType = consts.SubjectTypePairwise
		}), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewLocalValidator(newCIBAConfig(tc.config))

			err := validator.ValidateClientRegistrationMetadata(t.Context(), nil, tc.metadata)

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
		})
	}

	t.Run("ShouldApplyOnUpdate", func(t *testing.T) {
		ctx := context.Background()
		handler, registrar, config, _ := newConfigurationHandler(t)
		config.TokenEndpointHandlers.Append(cibaGrantHandler{})

		created := registerClient(t, ctx, registrar)

		requester := oauth2.NewClientConfigurationRequest()
		requester.Method = http.MethodPut
		requester.ClientID = created["client_id"].(string)
		requester.Signature = handler.Strategy.ClientRegistrationTokenSignature(ctx, created["registration_access_token"].(string))
		requester.Metadata = valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelTokenDeliveryMode = "fax" })

		err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
	})

	t.Run("ShouldEchoUserCodeWhenUnsupported", func(t *testing.T) {
		ctx := context.Background()
		_, registrar, config, _ := newConfigurationHandler(t)
		config.TokenEndpointHandlers.Append(cibaGrantHandler{})

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = valid(func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelUserCodeParameter = true })

		responder := oauth2.NewClientRegistrationResponse()

		require.NoError(t, registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))
		assert.Equal(t, true, responder.ToMap()[consts.ClientMetadataBackChannelUserCodeParameter])
	})
}

func TestSectorDocumentMustListCIBAURIs(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/jwks":
			_, _ = rw.Write([]byte(`["https://example.com/jwks"]`))
		case "/notify":
			_, _ = rw.Write([]byte(`["https://example.com/notify"]`))
		default:
			_, _ = rw.Write([]byte(`["https://example.com/other"]`))
		}
	}))

	t.Cleanup(server.Close)

	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil
	httpClient.RetryMax = 0
	httpClient.HTTPClient = server.Client()

	validator := NewSectorIdentifierValidator(&oauth2.Config{HTTPClient: httpClient})

	testCases := []struct {
		name     string
		path     string
		mode     string
		expected string
	}{
		{"ShouldAcceptPollListingJWKSURI", "/jwks", consts.CIBAModePoll, ""},
		{"ShouldAcceptPushListingEndpoint", "/notify", consts.CIBAModePush, ""},
		{"ShouldRejectPollMissingJWKSURI", "/other", consts.CIBAModePoll, "The 'sector_identifier_uri' document does not contain the 'jwks_uri' value 'https://example.com/jwks'."},
		{"ShouldRejectPingMissingJWKSURI", "/notify", consts.CIBAModePing, "The 'sector_identifier_uri' document does not contain the 'jwks_uri' value 'https://example.com/jwks'."},
		{"ShouldRejectPushMissingEndpoint", "/jwks", consts.CIBAModePush, "The 'sector_identifier_uri' document does not contain the 'backchannel_client_notification_endpoint' value 'https://example.com/notify'."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
				SectorIdentifierURI:                   server.URL + tc.path,
				SubjectType:                           consts.SubjectTypePairwise,
				BackChannelTokenDeliveryMode:          tc.mode,
				JSONWebKeysURI:                        "https://example.com/jwks",
				BackChannelClientNotificationEndpoint: "https://example.com/notify",
			})

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.expected)
		})
	}
}
