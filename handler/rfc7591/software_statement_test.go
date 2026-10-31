// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testStatementIssuer      = "https://statements.example.com"
	testStatementOtherIssuer = "https://other-statements.example.com"
	testStatementKeyID       = "statement-1"
	testStatementSoftwareID  = "4NRB1-0XZABZI9E6-5SM3R"
	testMetadataClientName   = "client_name"
	testMetadataSoftwareID   = "software_id"
	testStatementNotAJWT     = "not-a-jwt"
	testStatementRedirectURI = "https://client.example.com/cb"
	testStatementClientName  = "From Statement"
	testStatementVendorValue = "enabled"
	testStatementVendorClaim = "https://statements.example.com/vendor_feature"

	testStatementLargeNumberName = "https://client.example.com/large_number"
	testStatementLargeNumber     = "9007199254740993"

	testStatementUnapprovedReason = "The software statement issuer 'https://statements.example.com' is not approved."
	testStatementNotSignedReason  = "is not a signed JWT"
	testUnexpectedHS256Reason     = "unexpected signature algorithm 'HS256'"
	testStatementInvalidTypReason = "token was signed with an invalid typ"
	testStatementType             = consts.JSONWebTokenTypeSoftwareStatement

	testStatementCustomType         = "ssa+jwt"
	testStatementNoSoftwareIDReason = "the software statement does not have a 'software_id' claim"
	testStatementUnchanged          = "Unchanged"
)

func TestApplySoftwareStatement(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	testCases := []struct {
		name      string
		statement func(t *testing.T) string
		issuers   []oauth2.RFC7591TrustedIssuer
		configure func(config *oauth2.Config)
		err       error
		reason    string
	}{
		{
			name:      "ShouldAcceptAnApprovedStatement",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
		},
		{
			name: "ShouldRejectAnUnapprovedIssuer",
			statement: func(t *testing.T) string {
				return fixture.sign(t, jwt.MapClaims{jwt.ClaimIssuer: testStatementOtherIssuer})
			},
			err:    oauth2.ErrUnapprovedSoftwareStatement,
			reason: "The software statement issuer 'https://other-statements.example.com' is not approved.",
		},
		{
			name:      "ShouldRejectEveryStatementWithoutApprovedIssuers",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
			issuers:   []oauth2.RFC7591TrustedIssuer{},
			err:       oauth2.ErrUnapprovedSoftwareStatement,
			reason:    testStatementUnapprovedReason,
		},
		{
			name:      "ShouldNeverMatchAnIssuerWithoutKeys",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
			issuers:   []oauth2.RFC7591TrustedIssuer{{Issuer: testStatementIssuer}},
			err:       oauth2.ErrUnapprovedSoftwareStatement,
			reason:    testStatementUnapprovedReason,
		},
		{
			name:      "ShouldRejectAStatementWithoutAnIssuer",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{jwt.ClaimIssuer: nil}) },
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    "does not have an 'iss' claim",
		},
		{
			name:      "ShouldRejectAValueThatIsNotAJWT",
			statement: func(t *testing.T) string { return testStatementNotAJWT },
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    testStatementNotSignedReason,
		},
		{
			name:      "ShouldRejectAnEncryptedStatement",
			statement: func(t *testing.T) string { return "a.b.c.d.e" },
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    testStatementNotSignedReason,
		},
		{
			name:      "ShouldRejectAnUnsignedStatement",
			statement: func(t *testing.T) string { return unsignedJWT(t, softwareStatementClaims(nil)) },
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    "unexpected signature algorithm 'none'",
		},
		{
			name: "ShouldRejectASymmetricallySignedStatement",
			statement: func(t *testing.T) string {
				return hmacJWT(t, softwareStatementClaims(nil), testStatementKeyID)
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testUnexpectedHS256Reason,
		},
		{
			name: "ShouldRejectAStatementSignedByAnUnpublishedKey",
			statement: func(t *testing.T) string {
				return signSoftwareStatement(t, gen.MustRSAKey(), testStatementKeyID, softwareStatementClaims(nil))
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: "error in cryptographic primitive",
		},
		{
			name: "ShouldRejectAnExpiredStatement",
			statement: func(t *testing.T) string {
				return fixture.sign(t, jwt.MapClaims{jwt.ClaimExpirationTime: time.Now().Add(-time.Minute).Unix()})
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: "Token is expired",
		},
		{
			name: "ShouldRejectAStatementNotYetValid",
			statement: func(t *testing.T) string {
				return fixture.sign(t, jwt.MapClaims{jwt.ClaimNotBefore: time.Now().Add(time.Hour).Unix()})
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: "Token is not valid yet",
		},
		{
			name: "ShouldRejectAnAccessTokenPresentedAsAStatement",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, jwt.JSONWebTokenTypeAccessToken, softwareStatementClaims(nil))
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldRejectAnotherExplicitType",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, consts.JSONWebTokenTypeLogoutToken, softwareStatementClaims(nil))
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldRejectAStatementTypedJWTByDefault",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, jwt.JSONWebTokenTypeJWT, softwareStatementClaims(nil))
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldAcceptAStatementTypedJWTWhenConfigured",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, jwt.JSONWebTokenTypeJWT, softwareStatementClaims(nil))
			},
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementType, jwt.JSONWebTokenTypeJWT}
			},
		},
		{
			name: "ShouldRejectAStatementWithoutATypeByDefault",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, "", softwareStatementClaims(nil))
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldRejectAStatementWithoutATypeWhenAllowedWithoutJWT",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, "", softwareStatementClaims(nil))
			},
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType = true
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldAcceptAStatementWithoutATypeWhenAllowed",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, "", softwareStatementClaims(nil))
			},
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType = true
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementType, jwt.JSONWebTokenTypeJWT}
			},
		},
		{
			name: "ShouldAcceptTheMediaTypeForm",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, "application/"+testStatementType, softwareStatementClaims(nil))
			},
		},
		{
			name: "ShouldAcceptAConfiguredType",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, testStatementCustomType, softwareStatementClaims(nil))
			},
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementCustomType}
			},
		},
		{
			name:      "ShouldRejectTheSuggestedTypeWhenOnlyAnotherIsAllowed",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementCustomType}
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name: "ShouldRejectJWTWhenOnlyTheSuggestedTypeIsAllowed",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, jwt.JSONWebTokenTypeJWT, softwareStatementClaims(nil))
			},
			configure: func(config *oauth2.Config) {
				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementType}
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementInvalidTypReason,
		},
		{
			name:      "ShouldAcceptAStatementWithoutASoftwareIDByDefault",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{testMetadataSoftwareID: nil}) },
		},
		{
			name:      "ShouldRejectAStatementWithoutASoftwareIDWhenRequired",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{testMetadataSoftwareID: nil}) },
			configure: requireSoftwareID,
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    testStatementNoSoftwareIDReason,
		},
		{
			name:      "ShouldRejectAnEmptySoftwareIDWhenRequired",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{testMetadataSoftwareID: ""}) },
			configure: requireSoftwareID,
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    testStatementNoSoftwareIDReason,
		},
		{
			name:      "ShouldRejectASoftwareIDThatIsNotAStringWhenRequired",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{testMetadataSoftwareID: 42}) },
			configure: requireSoftwareID,
			err:       oauth2.ErrInvalidSoftwareStatement,
			reason:    testStatementNoSoftwareIDReason,
		},
		{
			name:      "ShouldAcceptAStatementWithASoftwareIDWhenRequired",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
			configure: requireSoftwareID,
		},
		{
			name:      "ShouldAcceptAStatementWithAnAudience",
			statement: func(t *testing.T) string { return fixture.sign(t, jwt.MapClaims{jwt.ClaimAudience: testEndpoint}) },
		},
		{
			name: "ShouldRejectAnIDTokenWhenASoftwareIDIsRequired",
			statement: func(t *testing.T) string {
				return signTypedSoftwareStatement(t, fixture.key, testStatementKeyID, jwt.JSONWebTokenTypeJWT, softwareStatementClaims(jwt.MapClaims{
					jwt.ClaimAudience:              "relying-party",
					jwt.ClaimSubject:               "user-1",
					"nonce":                        "n-0S6_WzA2Mj",
					consts.ClaimAuthenticationTime: time.Now().Unix(),
					testMetadataSoftwareID:         nil,
				}))
			},
			configure: func(config *oauth2.Config) {
				requireSoftwareID(config)

				config.RFC7591SoftwareStatementJWTValidationHeaderAllowTypes = []string{testStatementType, jwt.JSONWebTokenTypeJWT}
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testStatementNoSoftwareIDReason,
		},
		{
			name: "ShouldRejectASymmetricAlgorithmNamingAPublishedKey",
			statement: func(t *testing.T) string {
				return hmacJWTWithKeyID(t, softwareStatementClaims(nil), testStatementKeyID)
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: testUnexpectedHS256Reason,
		},
		{
			name: "ShouldAcceptAStatementWithoutAKeyIDWhenOneKeyMatches",
			statement: func(t *testing.T) string {
				return signSoftwareStatement(t, fixture.key, "", softwareStatementClaims(nil))
			},
		},
		{
			name:      "ShouldReportAnUnreachableKeySetAsAServerError",
			statement: func(t *testing.T) string { return fixture.sign(t, nil) },
			issuers:   []oauth2.RFC7591TrustedIssuer{{Issuer: testStatementIssuer, JSONWebKeysURI: "http://127.0.0.1:1/jwks.json"}},
			err:       oauth2.ErrServerError,
			reason:    "The keys of the software statement issuer could not be retrieved.",
		},
		{
			name: "ShouldRejectAClaimOfTheWrongType",
			statement: func(t *testing.T) string {
				return fixture.sign(t, jwt.MapClaims{consts.ClientMetadataRedirectURIs: testStatementRedirectURI})
			},
			err:    oauth2.ErrInvalidSoftwareStatement,
			reason: "cannot unmarshal string into Go struct field",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := fixture.config(tc.issuers)

			if tc.configure != nil {
				tc.configure(config)
			}

			metadata := &oauth2.ClientRegistrationMetadata{SoftwareStatement: tc.statement(t)}

			err := applySoftwareStatement(context.Background(), config, metadata)

			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.reason)
			}
		})
	}
}

func TestApplySoftwareStatementMergesClaims(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	statement := fixture.sign(t, jwt.MapClaims{
		testMetadataClientName:                        testStatementClientName,
		consts.ClientMetadataGrantTypes:               []any{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		consts.ClientRegistrationResponseClientID:     "forged-client",
		consts.ClientRegistrationResponseClientSecret: "forged-secret",
		consts.ClientMetadataSoftwareStatement:        "nested",
		"registration_access_token":                   "forged-token",
		"registration_client_uri":                     "https://evil.example.com/register/forged",
		"client_id_issued_at":                         1,
		"client_secret_expires_at":                    1,
		testStatementVendorClaim:                      testStatementVendorValue,
	})

	metadata := &oauth2.ClientRegistrationMetadata{
		RedirectURIs:      []string{testStatementRedirectURI},
		ClientName:        "From Request",
		GrantTypes:        []string{consts.GrantTypeClientCredentials},
		SoftwareStatement: statement,
		Extra:             map[string]any{testStatementLargeNumberName: json.Number(testStatementLargeNumber)},
	}

	require.NoError(t, applySoftwareStatement(context.Background(), fixture.config(nil), metadata))

	assert.Equal(t, testStatementClientName, metadata.ClientName)
	assert.Equal(t, []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}, metadata.GrantTypes)
	assert.Equal(t, testStatementSoftwareID, metadata.SoftwareID)
	assert.Equal(t, []string{testStatementRedirectURI}, metadata.RedirectURIs)
	assert.Equal(t, statement, metadata.SoftwareStatement)
	assert.Equal(t, map[string]any{testStatementVendorClaim: testStatementVendorValue, testStatementLargeNumberName: json.Number(testStatementLargeNumber)}, metadata.Extra)
	assert.Equal(t, []string{testMetadataClientName, consts.ClientMetadataGrantTypes, testStatementVendorClaim, testMetadataSoftwareID}, metadata.SoftwareStatementMembers)
}

func TestApplySoftwareStatementTakesPrecedenceOverCaseVariants(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	testCases := []struct {
		name    string
		member  string
		variant string
		forged  any
		claim   any
		get     func(metadata *oauth2.ClientRegistrationMetadata) any
		want    any
	}{
		{
			name:    "ShouldIgnoreUnicodeFoldOfScope",
			member:  consts.ClientMetadataScope,
			variant: "\u017fcope",
			forged:  "evil",
			claim:   "good",
			get:     func(metadata *oauth2.ClientRegistrationMetadata) any { return metadata.Scope },
			want:    "good",
		},
		{
			name:    "ShouldIgnoreUpperCaseScope",
			member:  consts.ClientMetadataScope,
			variant: "SCOPE",
			forged:  "evil",
			claim:   "good",
			get:     func(metadata *oauth2.ClientRegistrationMetadata) any { return metadata.Scope },
			want:    "good",
		},
		{
			name:    "ShouldIgnoreUnicodeFoldOfRedirectURIs",
			member:  "redirect_uris",
			variant: "redirect_uri\u017f",
			forged:  []string{"https://evil.example.com/cb"},
			claim:   []any{testStatementRedirectURI},
			get:     func(metadata *oauth2.ClientRegistrationMetadata) any { return metadata.RedirectURIs },
			want:    []string{testStatementRedirectURI},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statement := fixture.sign(t, jwt.MapClaims{tc.member: tc.claim})

			body, err := json.Marshal(map[string]any{tc.variant: tc.forged, consts.ClientMetadataSoftwareStatement: statement})
			require.NoError(t, err)

			metadata := &oauth2.ClientRegistrationMetadata{}
			require.NoError(t, json.Unmarshal(body, metadata))

			require.NoError(t, applySoftwareStatement(context.Background(), fixture.config(nil), metadata))

			assert.Equal(t, tc.want, tc.get(metadata))
			assert.Contains(t, metadata.SoftwareStatementMembers, tc.member)
			assert.NotContains(t, metadata.Extra, tc.variant)
		})
	}
}

func TestApplySoftwareStatementKeepsEmptyArrays(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	t.Run("ShouldKeepAnEmptyArrayTheStatementDoesNotMention", func(t *testing.T) {
		metadata := &oauth2.ClientRegistrationMetadata{
			AuthorizationDetailsTypes: []string{},
			SoftwareStatement:         fixture.sign(t, jwt.MapClaims{testMetadataClientName: testStatementClientName}),
		}

		require.NoError(t, applySoftwareStatement(context.Background(), fixture.config(nil), metadata))

		assert.NotNil(t, metadata.AuthorizationDetailsTypes)
		assert.Empty(t, metadata.AuthorizationDetailsTypes)
		assert.Nil(t, metadata.Contacts)
	})

	t.Run("ShouldLetTheStatementReplaceAnEmptyArray", func(t *testing.T) {
		metadata := &oauth2.ClientRegistrationMetadata{
			AuthorizationDetailsTypes: []string{},
			SoftwareStatement:         fixture.sign(t, jwt.MapClaims{"authorization_details_types": []any{"payment_initiation"}}),
		}

		require.NoError(t, applySoftwareStatement(context.Background(), fixture.config(nil), metadata))

		assert.Equal(t, []string{"payment_initiation"}, metadata.AuthorizationDetailsTypes)
	})
}

func TestApplySoftwareStatementWithoutStatement(t *testing.T) {
	metadata := &oauth2.ClientRegistrationMetadata{ClientName: testStatementUnchanged, SoftwareStatementMembers: []string{testMetadataClientName}}

	require.NoError(t, applySoftwareStatement(context.Background(), &oauth2.Config{}, metadata))
	assert.Equal(t, &oauth2.ClientRegistrationMetadata{ClientName: testStatementUnchanged}, metadata)
}

func TestClientRegistrationHandlerSoftwareStatement(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	for name, factory := range policyTestStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldRegisterAndReturnTheStatementValues", func(t *testing.T) {
				handler, store, _ := newPolicyRegistrationHandler(t, factory)
				fixture.configure(handler.Config.(*oauth2.Config))

				requester := policyRegistrationRequest(policyHandlerExample(0), policyHandlerKey)
				requester.Metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{testMetadataClientName: testStatementClientName})

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, responder))
				assert.Equal(t, http.StatusCreated, responder.GetStatusCode())

				values := responder.ToMap()
				assert.Equal(t, testStatementClientName, values[testMetadataClientName])
				assert.NotContains(t, values, "software_statement_members")

				client, err := store.GetClient(context.Background(), responder.ClientID)
				require.NoError(t, err)

				vouched, ok := client.(oauth2.SoftwareStatementClient)
				require.True(t, ok)
				assert.Equal(t, []string{testMetadataClientName, testMetadataSoftwareID}, vouched.GetSoftwareStatementMembers())
				assert.Equal(t, testStatementSoftwareID, values[testMetadataSoftwareID])
				assert.Equal(t, requester.Metadata.SoftwareStatement, values[consts.ClientMetadataSoftwareStatement])
			})

			t.Run("ShouldNotRecordMembersThatWereDropped", func(t *testing.T) {
				handler, store, _ := newPolicyRegistrationHandler(t, factory)
				fixture.configure(handler.Config.(*oauth2.Config))

				requester := policyRegistrationRequest(policyHandlerExample(0), policyHandlerKey)
				requester.Metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{
					testMetadataClientName: testStatementClientName,
					"azp":                  "ordinary-claim",
					"name":                 "ordinary-claim",
				})

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, responder))

				client, err := store.GetClient(context.Background(), responder.ClientID)
				require.NoError(t, err)

				vouched, ok := client.(oauth2.SoftwareStatementClient)
				require.True(t, ok)
				assert.Equal(t, []string{testMetadataClientName, testMetadataSoftwareID}, vouched.GetSoftwareStatementMembers())
			})

			t.Run("ShouldApplyThePolicyToTheStatementValues", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)
				fixture.configure(handler.Config.(*oauth2.Config))

				requester := policyRegistrationRequest(policyHandlerExample(0), policyHandlerKey)
				requester.Metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{
					consts.ClientMetadataGrantTypes: []any{consts.GrantTypeAuthorizationCode, consts.GrantTypeClientCredentials},
				})

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The 'grant_types' value 'client_credentials' is not permitted by the registration policy.")
				assert.Empty(t, memory.Clients)
			})

			t.Run("ShouldValidateTheStatementValues", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)
				fixture.configure(handler.Config.(*oauth2.Config))

				requester := policyRegistrationRequest(nil, "")
				requester.Metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{
					consts.ClientMetadataRedirectURIs: []any{"http://client.example.com/cb"},
				})

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI)
				assert.Empty(t, memory.Clients)
			})

			t.Run("ShouldRejectAnUnapprovedStatementBeforeRegistering", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				requester := policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey)
				requester.Metadata.SoftwareStatement = fixture.sign(t, nil)

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrUnapprovedSoftwareStatement)
				assert.Empty(t, memory.Clients)
				assert.Zero(t, memory.ClientRegistrationCounts[policyHandlerKey])
			})
		})
	}
}

func TestClientConfigurationHandlerStoredSoftwareStatement(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	for name, factory := range policyTestStores() {
		t.Run(name, func(t *testing.T) {
			setup := func(t *testing.T) (policy *policyConfigurationFixture, statement string) {
				policy = newPolicyConfigurationFixture(t, factory, policyHandlerExample(0))
				fixture.configure(policy.handler.Config.(*oauth2.Config))

				statement = fixture.sign(t, jwt.MapClaims{testMetadataClientName: testStatementClientName})

				metadata := policy.inPolicy("stored")
				metadata.SoftwareStatement = statement

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, policy.put(t, policy.token, metadata, responder))

				policy.token = responder.ToMap()[consts.ClientRegistrationResponseRegistrationAccessToken].(string)
				policy.handler.Config.(*oauth2.Config).RFC7591SoftwareStatementIssuers = nil

				return policy, statement
			}

			t.Run("ShouldAcceptTheStoredStatementOnceItsIssuerIsRetired", func(t *testing.T) {
				policy, statement := setup(t)

				metadata := policy.inPolicy("self-asserted")
				metadata.SoftwareStatement = statement

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, policy.put(t, policy.token, metadata, responder))
				assert.Equal(t, testStatementClientName, responder.ToMap()[testMetadataClientName])

				client, err := policy.store.GetClient(context.Background(), policy.id)
				require.NoError(t, err)

				vouched, ok := client.(oauth2.SoftwareStatementClient)
				require.True(t, ok)
				assert.Equal(t, []string{testMetadataClientName, testMetadataSoftwareID}, vouched.GetSoftwareStatementMembers())
			})

			t.Run("ShouldVerifyADifferentStatement", func(t *testing.T) {
				policy, _ := setup(t)

				metadata := policy.inPolicy("different")
				metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{testMetadataClientName: "Another"})

				require.ErrorIs(t, policy.put(t, policy.token, metadata, oauth2.NewClientRegistrationResponse()), oauth2.ErrUnapprovedSoftwareStatement)
			})

			t.Run("ShouldVerifyAStoredStatementWithNoRecordOfVerification", func(t *testing.T) {
				policy, statement := setup(t)

				client, err := policy.store.GetClient(context.Background(), policy.id)
				require.NoError(t, err)

				legacy := *client.(*oauth2.DefaultRegisteredClient)
				legacy.SoftwareStatementMembers = nil

				require.NoError(t, policy.store.UpdateClient(context.Background(), policy.id, &legacy))

				metadata := policy.inPolicy("legacy")
				metadata.SoftwareStatement = statement

				require.ErrorIs(t, policy.put(t, policy.token, metadata, oauth2.NewClientRegistrationResponse()), oauth2.ErrUnapprovedSoftwareStatement)
			})
		})
	}
}

func TestClientConfigurationHandlerSoftwareStatement(t *testing.T) {
	fixture := newSoftwareStatementFixture(t)

	for name, factory := range policyTestStores() {
		t.Run(name, func(t *testing.T) {
			policy := newPolicyConfigurationFixture(t, factory, policyHandlerExample(0))
			fixture.configure(policy.handler.Config.(*oauth2.Config))

			t.Run("ShouldApplyTheStatementValuesOnUpdate", func(t *testing.T) {
				metadata := policy.inPolicy("updated")
				metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{testMetadataClientName: testStatementClientName})

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, policy.put(t, policy.token, metadata, responder))
				assert.Equal(t, testStatementClientName, responder.ToMap()[testMetadataClientName])

				policy.token = responder.ToMap()[consts.ClientRegistrationResponseRegistrationAccessToken].(string)
			})

			t.Run("ShouldRejectAnUnapprovedStatementOnUpdate", func(t *testing.T) {
				metadata := policy.inPolicy("unapproved")
				metadata.SoftwareStatement = fixture.sign(t, jwt.MapClaims{jwt.ClaimIssuer: testStatementOtherIssuer})

				err := policy.put(t, policy.token, metadata, oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrUnapprovedSoftwareStatement)
			})

			t.Run("ShouldRejectAnInvalidStatementOnUpdate", func(t *testing.T) {
				metadata := policy.inPolicy("rejected")
				metadata.SoftwareStatement = testStatementNotAJWT

				err := policy.put(t, policy.token, metadata, oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrInvalidSoftwareStatement)
			})
		})
	}
}

type softwareStatementFixture struct {
	key    any
	server string
}

func newSoftwareStatementFixture(t *testing.T) (fixture *softwareStatementFixture) {
	t.Helper()

	key := gen.MustRSAKey()

	server := newJWKSServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: testStatementKeyID, Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		{Key: []byte("a-symmetric-secret-that-is-at-least-32-bytes"), KeyID: testStatementKeyID + "-hs", Algorithm: string(jose.HS256), Use: jwt.JSONWebTokenUseSignature},
	}})

	return &softwareStatementFixture{key: key, server: server.URL}
}

func (f *softwareStatementFixture) issuers() []oauth2.RFC7591TrustedIssuer {
	return []oauth2.RFC7591TrustedIssuer{{Issuer: testStatementIssuer, JSONWebKeysURI: f.server}}
}

func (f *softwareStatementFixture) config(issuers []oauth2.RFC7591TrustedIssuer) (config *oauth2.Config) {
	if issuers == nil {
		issuers = f.issuers()
	}

	client := retryablehttp.NewClient()
	client.RetryMax = 0

	return &oauth2.Config{
		RFC7591SoftwareStatementIssuers: issuers,
		JWKSFetcherStrategy:             oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client)),
	}
}

func (f *softwareStatementFixture) configure(config *oauth2.Config) {
	config.RFC7591SoftwareStatementIssuers = f.issuers()
}

func (f *softwareStatementFixture) sign(t *testing.T, overrides jwt.MapClaims) string {
	t.Helper()

	return signSoftwareStatement(t, f.key, testStatementKeyID, softwareStatementClaims(overrides))
}

func requireSoftwareID(config *oauth2.Config) {
	config.RFC7591SoftwareStatementRequireSoftwareID = true
}

func signSoftwareStatement(t *testing.T, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()

	return signTypedSoftwareStatement(t, key, kid, testStatementType, claims)
}

func signTypedSoftwareStatement(t *testing.T, key any, kid, typ string, claims jwt.MapClaims) string {
	t.Helper()

	options := &jose.SignerOptions{}

	if kid != "" {
		options = options.WithHeader(jose.HeaderKey("kid"), kid)
	}

	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}

func softwareStatementClaims(overrides jwt.MapClaims) jwt.MapClaims {
	claims := jwt.MapClaims{
		jwt.ClaimIssuer:         testStatementIssuer,
		jwt.ClaimIssuedAt:       time.Now().Unix(),
		jwt.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		testMetadataSoftwareID:  testStatementSoftwareID,
	}

	for name, value := range overrides {
		if value == nil {
			delete(claims, name)

			continue
		}

		claims[name] = value
	}

	return claims
}

func unsignedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	return jwtSegment(t, map[string]any{"alg": consts.JSONWebTokenAlgNone}) + "." + jwtSegment(t, claims) + "."
}

func hmacJWT(t *testing.T, claims jwt.MapClaims, kid string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("a-symmetric-secret-that-is-at-least-32-bytes")}, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid+"-hs"))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}

func hmacJWTWithKeyID(t *testing.T, claims jwt.MapClaims, kid string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("a-symmetric-secret-that-is-at-least-32-bytes")}, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}

func jwtSegment(t *testing.T, value any) string {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(data)
}
