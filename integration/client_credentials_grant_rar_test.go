// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientCredentialsFlowWithAuthorizationDetails(t *testing.T) {
	const requested = `[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`

	testCases := []struct {
		name     string
		implicit bool
		types    []string
		details  string
		expected string
		err      string
	}{
		{
			name:     "ShouldIssueRequestedDetails",
			implicit: true,
			details:  requested,
			expected: requested,
		},
		{
			name:     "ShouldIssueRequestedDetailsOfAnAllowedType",
			implicit: true,
			types:    []string{internal.AuthorizationDetailsTypePaymentInitiation},
			details:  requested,
			expected: requested,
		},
		{
			name:     "ShouldIssueNoDetailsWhenNoneRequested",
			implicit: true,
		},
		{
			name:    "ShouldIssueNoDetailsWhenNoneGranted",
			details: requested,
		},
		{
			name:     "ShouldRejectTypeNotAllowedForClient",
			implicit: true,
			types:    []string{},
			details:  requested,
			err:      "invalid_authorization_details",
		},
		{
			name:     "ShouldRejectUnknownType",
			implicit: true,
			details:  `[{"type":"account_information"}]`,
			err:      "invalid_authorization_details",
		},
		{
			name:     "ShouldRejectDetailsNotConformingToTheType",
			implicit: true,
			details:  `[{"type":"payment_initiation","actions":["refund"]}]`,
			err:      "invalid_authorization_details",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := storage.NewMemoryStore()

			config := &oauth2.Config{
				AuthorizationDetailsTypeHandlers:            []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
				ClientCredentialsFlowImplicitGrantRequested: tc.implicit,
			}

			f := compose.Compose(config, s, hmacStrategy, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory)
			ts := mockServer(t, f, &openid.DefaultSession{Subject: testSubject})
			defer ts.Close()

			s.Clients[testClientIDRAR] = &internal.AuthorizationDetailsClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:           testClientIDRAR,
					ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
					GrantTypes:   []string{consts.GrantTypeClientCredentials},
					Scopes:       []string{testScopeOAuth2},
				},
				AuthorizationDetailsTypes: tc.types,
			}

			form := url.Values{
				consts.FormParameterGrantType: {consts.GrantTypeClientCredentials},
				consts.FormParameterScope:     {testScopeOAuth2},
			}

			if tc.details != "" {
				form.Set("authorization_details", tc.details)
			}

			token := postTokenEndpoint(t, ts, form)

			if tc.err != "" {
				var actual string

				require.NoError(t, json.Unmarshal(token["error"], &actual))
				assert.Equal(t, tc.err, actual)

				return
			}

			var access string

			require.NoError(t, json.Unmarshal(token["access_token"], &access))

			if tc.expected == "" {
				assert.NotContains(t, token, "authorization_details")
				assert.Empty(t, introspectAuthorizationDetails(t, ts, access))

				return
			}

			assert.JSONEq(t, tc.expected, string(token["authorization_details"]))
			assert.JSONEq(t, tc.expected, introspectAuthorizationDetails(t, ts, access))
		})
	}
}
