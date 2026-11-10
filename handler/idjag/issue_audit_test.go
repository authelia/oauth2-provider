// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.2
func TestIssueHandlerRequestCarriesTheAuditedValues(t *testing.T) {
	signing := gen.MustRSAKey()

	testCases := []struct {
		name     string
		audience string
		err      error
		expected oauth2.Arguments
	}{
		{name: "ShouldCarryTheResolvedAudienceOfAGrantedExchange", audience: issueAudienceURN, expected: oauth2.Arguments{redeemAudience}},
		{name: "ShouldCarryTheRequestedAudienceOfARefusedExchange", audience: redeemOther, err: oauth2.ErrInvalidTarget, expected: oauth2.Arguments{redeemOther}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewExampleStore()
			store.Clients[boundClient] = &oauth2.DefaultClient{
				ID:           boundClient,
				ClientSecret: oauth2.NewPlainTextClientSecret(boundSecret),
				GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
				Scopes:       []string{redeemRead},
			}

			relationship := oauth2.IDJAGRelationship{Issuer: redeemAudience, ClientID: redeemClient, Scopes: []string{redeemRead}, Resources: []string{redeemResource}}

			store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: boundClient, Audience: redeemAudience}] = relationship
			store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: boundClient, Audience: issueAudienceURN}] = relationship
			store.IDJAGAudienceSubjects[storage.IDJAGAudienceSubjectKey{Issuer: redeemAudience, Subject: issueSubject}] = issueMapped

			config := &oauth2.Config{
				GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
				RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				Issuer:                                boundIssuer,
				RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693IDJAG:   &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
					consts.TokenTypeRFC8693IDToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
				},
			}

			form := url.Values{
				consts.FormParameterGrantType: {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectToken: {signBound(t, signing, jose.RS256, "JWT", false, map[string]any{
					consts.ClaimIssuer:         boundIssuer,
					consts.ClaimSubject:        issueSubject,
					consts.ClaimAudience:       []string{boundClient},
					consts.ClaimExpirationTime: time.Now().Add(30 * time.Minute).Unix(),
					consts.ClaimIssuedAt:       time.Now().Unix(),
				})},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693IDToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
				consts.FormParameterAudience:           {tc.audience},
				consts.FormParameterResource:           {redeemResource},
				consts.FormParameterScope:              {redeemRead},
			}

			r := httptest.NewRequest(http.MethodPost, boundEndpoint, strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.Header.Set(consts.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(boundClient+":"+boundSecret)))

			provider := compose.ComposeAllEnabled(config, store, signing)

			request, err := provider.NewAccessRequest(t.Context(), r, rfc8693.NewDefaultSession())
			if err == nil {
				_, err = provider.NewAccessResponse(t.Context(), request)
			}

			require.NotNil(t, request)
			require.NotNil(t, request.GetClient())
			assert.Equal(t, boundClient, request.GetClient().GetID())

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.expected, request.GetRequestedAudience())
				assert.Equal(t, oauth2.Arguments{redeemResource}, request.GetRequestedResource())
				assert.Equal(t, oauth2.Arguments{redeemRead}, request.GetRequestedScopes())

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expected, request.GetGrantedAudience())
			assert.Equal(t, oauth2.Arguments{redeemResource}, request.GetGrantedResource())
			assert.Equal(t, oauth2.Arguments{redeemRead}, request.GetGrantedScopes())
		})
	}
}
