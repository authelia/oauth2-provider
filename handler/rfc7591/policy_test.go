// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const (
	policyErrorPrefix = "The value of one of the client metadata fields is invalid and the server has rejected this request. "
	redirectPrefix    = "The value of one or more redirection URIs is invalid. "

	policyTestClientName = "client_name"
	invalidTokenPrefix   = "The access token provided is expired, revoked, malformed, or invalid for other reasons. "

	policyTestCustom    = "my_attr"
	policyTestProfile   = "profile"
	policyTestEmail     = "email"
	policyTestOther     = "other_attr"
	policyTestTimetable = "timetable.read"

	policyMemberRedirectURIs = "redirect_uris"
	policyMemberAuthMethod   = "token_endpoint_auth_method"
	policyMemberAuthTime     = "require_auth_time"
	policyMemberContacts     = "contacts"

	policyMemberDefaultMaxAge             = "default_max_age"
	policyMemberAuthorizationDetailsTypes = "authorization_details_types"
	policyMemberEncryptedResponseKID      = "id_token_encrypted_response_kid"
	policyMemberIntrospectionSignedAlg    = "introspection_signed_response_alg"
	policyMemberUserinfoSignedKeyID       = "userinfo_signed_response_kid"

	policyTestAlgPS256       = "PS256"
	policyTestAlgRSAOAEP256  = "RSA-OAEP-256"
	policyTestKeyID          = "k1"
	policyHintInvalidPattern = "The registration policy member 'scope' rule 'pattern' is not a valid regular expression."

	policyHintUnevaluable = "The 'my_attr' value is not a type the registration policy can evaluate."

	policyHintNotObject       = "The registration policy must be a JSON object."
	policyHintScopeExactlyOne = "The registration policy member 'scope' must hold exactly one of 'pattern', 'one_of' or 'subset_of'."
	policyHintMaxPositive     = "The registration policy member 'max_registrations' must be a positive integer."
)

func TestParseRegistrationPolicy(t *testing.T) {
	testCases := []struct {
		name     string
		claim    any
		custom   []string
		expected string
	}{
		{
			name: "ShouldAcceptExamplePolicy",
			claim: map[string]any{
				policyMemberRedirectURIs:           map[string]any{policyRulePattern: "^https://[a-z0-9-]+\\.apps\\.example\\.com/oauth/callback$"},
				consts.ClientMetadataGrantTypes:    map[string]any{policyRuleSubsetOf: []any{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}},
				consts.ClientMetadataResponseTypes: map[string]any{policyRuleOneOf: []any{consts.ResponseTypeAuthorizationCodeFlow}},
				policyMemberAuthMethod:             map[string]any{policyRuleOneOf: []any{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}},
				consts.ClientMetadataScope:         map[string]any{policyRuleSubsetOf: []any{consts.ScopeOpenID, policyTestProfile, policyTestEmail, policyTestTimetable}},
				policyMemberMaxRegistrations:       1,
			},
		},
		{
			name:  "ShouldAcceptBooleanMember",
			claim: map[string]any{policyMemberAuthTime: map[string]any{policyRuleOneOf: []any{"false"}}},
		},
		{
			name:   "ShouldAcceptDeclaredCustomMember",
			claim:  map[string]any{policyTestCustom: map[string]any{policyRulePattern: "^a$"}},
			custom: []string{policyTestCustom},
		},
		{
			name:     "ShouldRejectNonObject",
			claim:    "not an object",
			expected: policyHintNotObject,
		},
		{
			name:     "ShouldRejectNull",
			claim:    nil,
			expected: policyHintNotObject,
		},
		{
			name:     "ShouldRejectUnknownMember",
			claim:    map[string]any{"redirect_uri": map[string]any{policyRulePattern: "x"}},
			expected: "The registration policy member 'redirect_uri' is not a known client metadata member.",
		},
		{
			name:     "ShouldRejectUndeclaredCustomMember",
			claim:    map[string]any{policyTestCustom: map[string]any{policyRulePattern: "x"}},
			expected: "The registration policy member 'my_attr' is not a known client metadata member.",
		},
		{
			name:     "ShouldRejectJWKS",
			claim:    map[string]any{policyMemberJWKS: map[string]any{policyRulePattern: "x"}},
			expected: "The registration policy member 'jwks' cannot be constrained.",
		},
		{
			name:     "ShouldRejectEmptyRule",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{}},
			expected: policyHintScopeExactlyOne,
		},
		{
			name:     "ShouldRejectTwoRules",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRulePattern: "x", policyRuleOneOf: []any{"a"}}},
			expected: policyHintScopeExactlyOne,
		},
		{
			name:     "ShouldRejectUnknownRule",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{"regex": "x"}},
			expected: "The registration policy member 'scope' has the unknown rule 'regex'.",
		},
		{
			name:     "ShouldRejectNonStringPattern",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRulePattern: 1}},
			expected: "The registration policy member 'scope' rule 'pattern' must be a string.",
		},
		{
			name:     "ShouldRejectNonArrayOneOf",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRuleOneOf: "a"}},
			expected: "The registration policy member 'scope' rule 'one_of' must be an array of strings.",
		},
		{
			name:     "ShouldRejectNonStringSubsetOfElement",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRuleSubsetOf: []any{"a", 1}}},
			expected: "The registration policy member 'scope' rule 'subset_of' must be an array of strings.",
		},
		{
			name:     "ShouldRejectInvalidPattern",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRulePattern: "("}},
			expected: policyHintInvalidPattern,
		},
		{
			name:     "ShouldRejectPatternNestingTooDeepWhenAnchored",
			claim:    map[string]any{consts.ClientMetadataScope: map[string]any{policyRulePattern: strings.Repeat("(", 999) + "a" + strings.Repeat(")", 999)}},
			expected: policyHintInvalidPattern,
		},
		{
			name:     "ShouldRejectZeroMaxRegistrations",
			claim:    map[string]any{policyMemberMaxRegistrations: 0},
			expected: policyHintMaxPositive,
		},
		{
			name:     "ShouldRejectNegativeMaxRegistrations",
			claim:    map[string]any{policyMemberMaxRegistrations: -1},
			expected: policyHintMaxPositive,
		},
		{
			name:     "ShouldRejectFractionalMaxRegistrations",
			claim:    map[string]any{policyMemberMaxRegistrations: 1.5},
			expected: policyHintMaxPositive,
		},
		{
			name:     "ShouldRejectStringMaxRegistrations",
			claim:    map[string]any{policyMemberMaxRegistrations: "1"},
			expected: policyHintMaxPositive,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ParseRegistrationPolicy(tc.claim, tc.custom, true)

			if tc.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, policy)

				return
			}

			require.Error(t, err)
			assert.Nil(t, policy)
			assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+tc.expected)
		})
	}
}

func TestRegistrationPolicyCheck(t *testing.T) {
	const (
		redirectOK = "https://a.apps.example.com/oauth/callback"
		notPermit  = "The '%s' value '%s' is not permitted by the registration policy."
		required   = "The '%s' value is required by the registration policy."
	)

	example := map[string]any{
		policyMemberRedirectURIs:           map[string]any{policyRulePattern: "https://[a-z0-9-]+\\.apps\\.example\\.com/oauth/callback"},
		consts.ClientMetadataGrantTypes:    map[string]any{policyRuleSubsetOf: []any{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}},
		consts.ClientMetadataResponseTypes: map[string]any{policyRuleOneOf: []any{consts.ResponseTypeAuthorizationCodeFlow}},
		policyMemberAuthMethod:             map[string]any{policyRuleOneOf: []any{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}},
		consts.ClientMetadataScope:         map[string]any{policyRuleSubsetOf: []any{consts.ScopeOpenID, policyTestProfile, policyTestEmail, policyTestTimetable}},
	}

	valid := func() oauth2.ClientRegistrationMetadata {
		return oauth2.ClientRegistrationMetadata{
			RedirectURIs:            []string{redirectOK},
			GrantTypes:              []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
			ResponseTypes:           []string{consts.ResponseTypeAuthorizationCodeFlow},
			TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			Scope:                   "openid email",
		}
	}

	mutate := func(f func(m *oauth2.ClientRegistrationMetadata)) oauth2.ClientRegistrationMetadata {
		m := valid()

		f(&m)

		return m
	}

	rule := func(kind string, values ...any) map[string]any {
		return map[string]any{kind: values}
	}

	maxAge := int64(60)

	testCases := []struct {
		name     string
		policy   map[string]any
		custom   []string
		metadata oauth2.ClientRegistrationMetadata
		expected string
		err      error
	}{
		{
			name:     "ShouldPassInPolicyRequest",
			policy:   example,
			metadata: valid(),
		},
		{
			name:   "ShouldRejectRedirectURIOutsidePattern",
			policy: example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) {
				m.RedirectURIs = []string{"https://evil.example/oauth/callback"}
			}),
			expected: fmt.Sprintf(notPermit, policyMemberRedirectURIs, "https://evil.example/oauth/callback"),
			err:      oauth2.ErrInvalidRedirectURI,
		},
		{
			name:     "ShouldAnchorPattern",
			policy:   example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) { m.RedirectURIs = []string{redirectOK + "/x"} }),
			expected: fmt.Sprintf(notPermit, policyMemberRedirectURIs, redirectOK+"/x"),
			err:      oauth2.ErrInvalidRedirectURI,
		},
		{
			name:     "ShouldRequireJSONWebKeysURIWhenConstrained",
			policy:   map[string]any{consts.ClientMetadataJSONWebKeysURI: rule(policyRuleOneOf, "https://keys.example.com/jwks")},
			metadata: oauth2.ClientRegistrationMetadata{},
			expected: fmt.Sprintf(required, consts.ClientMetadataJSONWebKeysURI),
		},
		{
			name:     "ShouldRejectInlineKeysInPlaceOfAConstrainedJSONWebKeysURI",
			policy:   map[string]any{consts.ClientMetadataJSONWebKeysURI: rule(policyRuleOneOf, "https://keys.example.com/jwks")},
			metadata: oauth2.ClientRegistrationMetadata{JSONWebKeys: &jose.JSONWebKeySet{}},
			expected: fmt.Sprintf(required, consts.ClientMetadataJSONWebKeysURI),
		},
		{
			name:     "ShouldAcceptAConstrainedJSONWebKeysURI",
			policy:   map[string]any{consts.ClientMetadataJSONWebKeysURI: rule(policyRuleOneOf, "https://keys.example.com/jwks")},
			metadata: oauth2.ClientRegistrationMetadata{JSONWebKeysURI: "https://keys.example.com/jwks"},
		},
		{
			name:     "ShouldCheckEachLanguageTaggedVariant",
			policy:   map[string]any{policyTestClientName: rule(policyRuleOneOf, "Example")},
			metadata: oauth2.ClientRegistrationMetadata{ClientName: "Example", Extra: map[string]any{policyTestClientName + "#en": "Example", policyTestClientName + "#ja-Jpan-JP": "Other"}},
			expected: fmt.Sprintf(notPermit, policyTestClientName+"#ja-Jpan-JP", "Other"),
		},
		{
			name:     "ShouldAcceptLanguageTaggedVariantsInPolicy",
			policy:   map[string]any{policyTestClientName: rule(policyRuleSubsetOf, "Example", "Beispiel")},
			metadata: oauth2.ClientRegistrationMetadata{ClientName: "Example", Extra: map[string]any{policyTestClientName + "#de": "Beispiel"}},
		},
		{
			name:     "ShouldIgnoreAnEmptyLanguageTag",
			policy:   map[string]any{policyTestClientName: rule(policyRuleOneOf, "Example")},
			metadata: oauth2.ClientRegistrationMetadata{ClientName: "Example", Extra: map[string]any{policyTestClientName + "#": "Other"}},
		},
		{
			name:     "ShouldCheckLanguageTaggedVariantsOfCustomMetadata",
			policy:   map[string]any{policyTestCustom: rule(policyRuleOneOf, "x")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: "x", policyTestCustom + "#de": "y"}},
			expected: fmt.Sprintf(notPermit, policyTestCustom+"#de", "y"),
		},
		{
			name:     "ShouldReportLanguageTaggedRedirectURIsAsRedirectURIErrors",
			policy:   map[string]any{policyMemberRedirectURIs: rule(policyRuleSubsetOf, redirectOK)},
			metadata: oauth2.ClientRegistrationMetadata{RedirectURIs: []string{redirectOK}, Extra: map[string]any{policyMemberRedirectURIs + "#en": []any{"https://evil.example"}}},
			expected: fmt.Sprintf(notPermit, policyMemberRedirectURIs+"#en", "https://evil.example"),
			err:      oauth2.ErrInvalidRedirectURI,
		},
		{
			name:     "ShouldRejectGrantTypeOutsideSubset",
			policy:   example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) { m.GrantTypes = []string{consts.GrantTypeClientCredentials} }),
			expected: fmt.Sprintf(notPermit, "grant_types", consts.GrantTypeClientCredentials),
		},
		{
			name:     "ShouldApplyDefaultAuthMethod",
			policy:   example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) { m.TokenEndpointAuthMethod = "" }),
			expected: fmt.Sprintf(notPermit, policyMemberAuthMethod, consts.ClientAuthMethodClientSecretBasic),
		},
		{
			name:   "ShouldRejectMultipleValuesForOneOf",
			policy: example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) {
				m.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}
			}),
			expected: "The 'response_types' value must be exactly one of the values permitted by the registration policy.",
		},
		{
			name:     "ShouldRejectScopeOutsideSubset",
			policy:   example,
			metadata: mutate(func(m *oauth2.ClientRegistrationMetadata) { m.Scope = "openid admin" }),
			expected: fmt.Sprintf(notPermit, policyMemberScope, "admin"),
		},
		{
			name:     "ShouldApplyDefaultApplicationType",
			policy:   map[string]any{"application_type": rule(policyRuleSubsetOf, "native")},
			expected: fmt.Sprintf(notPermit, "application_type", "web"),
		},
		{
			name:     "ShouldRequireServerChosenMember",
			policy:   map[string]any{"subject_type": rule(policyRuleSubsetOf, "pairwise")},
			expected: "The 'subject_type' value is required by the registration policy.",
		},
		{
			name:     "ShouldApplyBooleanDefault",
			policy:   map[string]any{policyMemberAuthTime: rule(policyRuleOneOf, "true")},
			expected: fmt.Sprintf(notPermit, policyMemberAuthTime, "false"),
		},
		{
			name:   "ShouldPassOmittedSubsetMember",
			policy: map[string]any{policyMemberContacts: rule(policyRuleSubsetOf, "a@example.com")},
		},
		{
			name:     "ShouldRejectOmittedOneOfMember",
			policy:   map[string]any{policyMemberContacts: rule(policyRuleOneOf, "a@example.com")},
			expected: "The 'contacts' value must be exactly one of the values permitted by the registration policy.",
		},
		{
			name:   "ShouldPassOmittedScopeForSubset",
			policy: map[string]any{consts.ClientMetadataScope: rule(policyRuleSubsetOf, "openid")},
		},
		{
			name:     "ShouldPassCustomString",
			policy:   map[string]any{policyTestCustom: rule(policyRuleOneOf, "x")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: "x"}},
		},
		{
			name:     "ShouldPassCustomArray",
			policy:   map[string]any{policyTestCustom: rule(policyRuleSubsetOf, "x", "y")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: []any{"x", "y"}}},
		},
		{
			name:     "ShouldPassCustomNumberAndBool",
			policy:   map[string]any{policyTestCustom: rule(policyRuleOneOf, "5"), policyTestOther: rule(policyRuleOneOf, "true")},
			custom:   []string{policyTestCustom, policyTestOther},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: json.Number("5"), policyTestOther: true}},
		},
		{
			name:     "ShouldRejectCustomUnsupportedType",
			policy:   map[string]any{policyTestCustom: rule(policyRuleOneOf, "x")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: map[string]any{}}},
			expected: policyHintUnevaluable,
		},
		{
			name:     "ShouldRejectCustomArrayOfNonStrings",
			policy:   map[string]any{policyTestCustom: rule(policyRuleSubsetOf, "x")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{Extra: map[string]any{policyTestCustom: []any{1}}},
			expected: policyHintUnevaluable,
		},
		{
			name:     "ShouldTreatAbsentCustomAsNoValues",
			policy:   map[string]any{policyTestCustom: rule(policyRuleSubsetOf, "x")},
			custom:   []string{policyTestCustom},
			metadata: oauth2.ClientRegistrationMetadata{},
		},
		{
			name:     "ShouldRequireRequestObjectSigningAlg",
			policy:   map[string]any{consts.ClientMetadataRequestObjectSigningAlg: rule(policyRuleSubsetOf, policyTestAlgPS256)},
			expected: fmt.Sprintf(required, consts.ClientMetadataRequestObjectSigningAlg),
		},
		{
			name:     "ShouldPassPresentRequestObjectSigningAlg",
			policy:   map[string]any{consts.ClientMetadataRequestObjectSigningAlg: rule(policyRuleSubsetOf, policyTestAlgPS256)},
			metadata: oauth2.ClientRegistrationMetadata{RequestObjectSigningAlg: policyTestAlgPS256},
		},
		{
			name:     "ShouldRequireRequestObjectSigningKeyID",
			policy:   map[string]any{"request_object_signing_kid": rule(policyRuleSubsetOf, policyTestKeyID)},
			expected: fmt.Sprintf(required, "request_object_signing_kid"),
		},
		{
			name:     "ShouldRequireRequestObjectEncryptionAlg",
			policy:   map[string]any{"request_object_encryption_alg": rule(policyRuleSubsetOf, policyTestAlgRSAOAEP256)},
			expected: fmt.Sprintf(required, "request_object_encryption_alg"),
		},
		{
			name:     "ShouldRequireRequestObjectEncryptionEnc",
			policy:   map[string]any{"request_object_encryption_enc": rule(policyRuleSubsetOf, "A256GCM")},
			metadata: oauth2.ClientRegistrationMetadata{RequestObjectEncryptionAlg: policyTestAlgRSAOAEP256},
			expected: fmt.Sprintf(required, "request_object_encryption_enc"),
		},
		{
			name:     "ShouldRequireRequestObjectEncryptionKeyID",
			policy:   map[string]any{"request_object_encryption_kid": rule(policyRuleSubsetOf, policyTestKeyID)},
			expected: fmt.Sprintf(required, "request_object_encryption_kid"),
		},
		{
			name:     "ShouldRequireTokenEndpointAuthSigningAlg",
			policy:   map[string]any{"token_endpoint_auth_signing_alg": rule(policyRuleSubsetOf, policyTestAlgPS256)},
			expected: fmt.Sprintf(required, "token_endpoint_auth_signing_alg"),
		},
		{
			name:     "ShouldRequireIntrospectionEndpointAuthSigningAlg",
			policy:   map[string]any{"introspection_endpoint_auth_signing_alg": rule(policyRuleSubsetOf, policyTestAlgPS256)},
			metadata: oauth2.ClientRegistrationMetadata{TokenEndpointAuthSigningAlg: policyTestAlgPS256},
			expected: fmt.Sprintf(required, "introspection_endpoint_auth_signing_alg"),
		},
		{
			name:     "ShouldRequireRevocationEndpointAuthSigningAlg",
			policy:   map[string]any{"revocation_endpoint_auth_signing_alg": rule(policyRuleSubsetOf, policyTestAlgPS256)},
			expected: fmt.Sprintf(required, "revocation_endpoint_auth_signing_alg"),
		},
		{
			name:     "ShouldEvaluateOmittedIntrospectionAuthMethodAsTokenMethod",
			policy:   map[string]any{consts.ClientMetadataIntrospectionEndpointAuthMethod: rule(policyRuleOneOf, consts.ClientAuthMethodPrivateKeyJWT)},
			metadata: oauth2.ClientRegistrationMetadata{TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT},
		},
		{
			name:     "ShouldEvaluateOmittedIntrospectionAuthMethodAsDefaultTokenMethod",
			policy:   map[string]any{consts.ClientMetadataIntrospectionEndpointAuthMethod: rule(policyRuleOneOf, consts.ClientAuthMethodPrivateKeyJWT)},
			expected: fmt.Sprintf(notPermit, consts.ClientMetadataIntrospectionEndpointAuthMethod, consts.ClientAuthMethodClientSecretBasic),
		},
		{
			name:     "ShouldEvaluateOmittedRevocationAuthMethodAsTokenMethod",
			policy:   map[string]any{"revocation_endpoint_auth_method": rule(policyRuleSubsetOf, consts.ClientAuthMethodPrivateKeyJWT)},
			metadata: oauth2.ClientRegistrationMetadata{TokenEndpointAuthMethod: consts.ClientAuthMethodNone},
			expected: fmt.Sprintf(notPermit, "revocation_endpoint_auth_method", consts.ClientAuthMethodNone),
		},
		{
			name:     "ShouldEvaluateOmittedEncryptedResponseEncAsDefault",
			policy:   map[string]any{"id_token_encrypted_response_enc": rule(policyRuleOneOf, "A256GCM")},
			metadata: oauth2.ClientRegistrationMetadata{IDTokenEncryptedResponseAlg: policyTestAlgRSAOAEP256},
			expected: fmt.Sprintf(notPermit, "id_token_encrypted_response_enc", "A128CBC-HS256"),
		},
		{
			name:     "ShouldEvaluateOmittedEncryptedResponseEncAsDefaultWithKeyID",
			policy:   map[string]any{"userinfo_encrypted_response_enc": rule(policyRuleSubsetOf, "A256GCM")},
			metadata: oauth2.ClientRegistrationMetadata{UserinfoEncryptedResponseKeyID: policyTestKeyID},
			expected: fmt.Sprintf(notPermit, "userinfo_encrypted_response_enc", "A128CBC-HS256"),
		},
		{
			name:     "ShouldPassDefaultEncryptedResponseEnc",
			policy:   map[string]any{"authorization_encrypted_response_enc": rule(policyRuleOneOf, "A128CBC-HS256")},
			metadata: oauth2.ClientRegistrationMetadata{AuthorizationEncryptedResponseAlg: policyTestAlgRSAOAEP256},
		},
		{
			name:   "ShouldTreatEncryptedResponseEncAsNoValuesWhenUnencrypted",
			policy: map[string]any{"introspection_encrypted_response_enc": rule(policyRuleSubsetOf, "A256GCM")},
		},
		{
			name:     "ShouldTreatEncryptedResponseEncAsNoValuesWhenAlgNone",
			policy:   map[string]any{"access_token_encrypted_response_enc": rule(policyRuleOneOf, "A256GCM")},
			metadata: oauth2.ClientRegistrationMetadata{AccessTokenEncryptedResponseAlg: consts.JSONWebTokenAlgNone},
			expected: "The 'access_token_encrypted_response_enc' value must be exactly one of the values permitted by the registration policy.",
		},
		{
			name:     "ShouldRequireEncryptedResponseAlgWithKeyID",
			policy:   map[string]any{consts.ClientMetadataIDTokenEncryptedResponseAlg: rule(policyRuleSubsetOf, policyTestAlgRSAOAEP256)},
			metadata: oauth2.ClientRegistrationMetadata{IDTokenEncryptedResponseKeyID: policyTestKeyID},
			expected: fmt.Sprintf(required, consts.ClientMetadataIDTokenEncryptedResponseAlg),
		},
		{
			name:   "ShouldTreatEncryptedResponseAlgAsNoValuesWhenUnencrypted",
			policy: map[string]any{consts.ClientMetadataIDTokenEncryptedResponseAlg: rule(policyRuleSubsetOf, policyTestAlgRSAOAEP256)},
		},
		{
			name:     "ShouldRequireEncryptedResponseKeyIDWithAlg",
			policy:   map[string]any{policyMemberEncryptedResponseKID: rule(policyRuleSubsetOf, policyTestKeyID)},
			metadata: oauth2.ClientRegistrationMetadata{IDTokenEncryptedResponseAlg: policyTestAlgRSAOAEP256},
			expected: fmt.Sprintf(required, policyMemberEncryptedResponseKID),
		},
		{
			name:   "ShouldTreatEncryptedResponseKeyIDAsNoValuesWhenUnencrypted",
			policy: map[string]any{policyMemberEncryptedResponseKID: rule(policyRuleSubsetOf, policyTestKeyID)},
		},
		{
			name:     "ShouldApplyDefaultAccessTokenSignedResponseAlg",
			policy:   map[string]any{"access_token_signed_response_alg": rule(policyRuleSubsetOf, policyTestAlgPS256)},
			expected: fmt.Sprintf(notPermit, "access_token_signed_response_alg", "RS256"),
		},
		{
			name:     "ShouldRequireAuthorizationSignedResponseAlg",
			policy:   map[string]any{"authorization_signed_response_alg": rule(policyRuleSubsetOf, policyTestAlgPS256)},
			expected: fmt.Sprintf(required, "authorization_signed_response_alg"),
		},
		{
			name:     "ShouldRequireIDTokenSignedResponseKeyID",
			policy:   map[string]any{"id_token_signed_response_kid": rule(policyRuleSubsetOf, policyTestKeyID)},
			expected: fmt.Sprintf(required, "id_token_signed_response_kid"),
		},
		{
			name:     "ShouldRequireIntrospectionSignedResponseAlgWithKeyID",
			policy:   map[string]any{policyMemberIntrospectionSignedAlg: rule(policyRuleSubsetOf, policyTestAlgPS256)},
			metadata: oauth2.ClientRegistrationMetadata{IntrospectionSignedResponseKeyID: policyTestKeyID},
			expected: fmt.Sprintf(required, policyMemberIntrospectionSignedAlg),
		},
		{
			name:   "ShouldTreatIntrospectionSignedResponseAlgAsNoValuesWhenUnsigned",
			policy: map[string]any{policyMemberIntrospectionSignedAlg: rule(policyRuleSubsetOf, policyTestAlgPS256)},
		},
		{
			name:     "ShouldRequireIntrospectionSignedResponseKeyIDWithAlg",
			policy:   map[string]any{"introspection_signed_response_kid": rule(policyRuleSubsetOf, policyTestKeyID)},
			metadata: oauth2.ClientRegistrationMetadata{IntrospectionSignedResponseAlg: policyTestAlgPS256},
			expected: fmt.Sprintf(required, "introspection_signed_response_kid"),
		},
		{
			name:     "ShouldRequireUserinfoSignedResponseKeyIDWithAlg",
			policy:   map[string]any{policyMemberUserinfoSignedKeyID: rule(policyRuleSubsetOf, policyTestKeyID)},
			metadata: oauth2.ClientRegistrationMetadata{UserinfoSignedResponseAlg: policyTestAlgPS256},
			expected: fmt.Sprintf(required, policyMemberUserinfoSignedKeyID),
		},
		{
			name:   "ShouldTreatUserinfoSignedResponseKeyIDAsNoValuesWhenUnsigned",
			policy: map[string]any{policyMemberUserinfoSignedKeyID: rule(policyRuleSubsetOf, policyTestKeyID)},
		},
		{
			name:     "ShouldRequireTokenExchangeSubjectTokenTypes",
			policy:   map[string]any{"token_exchange_subject_token_types": rule(policyRuleSubsetOf, consts.TokenTypeRFC8693AccessToken)},
			expected: fmt.Sprintf(required, "token_exchange_subject_token_types"),
		},
		{
			name:     "ShouldRequireTokenExchangeActorTokenTypes",
			policy:   map[string]any{"token_exchange_actor_token_types": rule(policyRuleSubsetOf, consts.TokenTypeRFC8693AccessToken)},
			expected: fmt.Sprintf(required, "token_exchange_actor_token_types"),
		},
		{
			name:     "ShouldRequireTokenExchangeRequestTokenTypes",
			policy:   map[string]any{"token_exchange_request_token_types": rule(policyRuleSubsetOf, consts.TokenTypeRFC8693AccessToken)},
			expected: fmt.Sprintf(required, "token_exchange_request_token_types"),
		},
		{
			name:     "ShouldRequireTokenExchangePermittedClientIDs",
			policy:   map[string]any{"token_exchange_permitted_client_ids": rule(policyRuleSubsetOf, "a")},
			expected: fmt.Sprintf(required, "token_exchange_permitted_client_ids"),
		},
		{
			name:     "ShouldRequireAuthorizationDetailsTypesWhenNil",
			policy:   map[string]any{policyMemberAuthorizationDetailsTypes: rule(policyRuleSubsetOf, "payment_initiation")},
			expected: fmt.Sprintf(required, policyMemberAuthorizationDetailsTypes),
		},
		{
			name:     "ShouldTreatEmptyAuthorizationDetailsTypesAsNoValues",
			policy:   map[string]any{policyMemberAuthorizationDetailsTypes: rule(policyRuleSubsetOf, "payment_initiation")},
			metadata: oauth2.ClientRegistrationMetadata{AuthorizationDetailsTypes: []string{}},
		},
		{
			name:     "ShouldEvaluateDefaultMaxAge",
			policy:   map[string]any{policyMemberDefaultMaxAge: rule(policyRuleOneOf, "300")},
			metadata: oauth2.ClientRegistrationMetadata{DefaultMaxAge: &maxAge},
			expected: fmt.Sprintf(notPermit, policyMemberDefaultMaxAge, "60"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ParseRegistrationPolicy(tc.policy, tc.custom, true)
			require.NoError(t, err)

			err = policy.Check(&tc.metadata)

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			if tc.err == oauth2.ErrInvalidRedirectURI {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI)
				assert.Equal(t, redirectPrefix+tc.expected, oauth2.ErrorToDebugRFC6749Error(err).Error())

				return
			}

			assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
			assert.Equal(t, policyErrorPrefix+tc.expected, oauth2.ErrorToDebugRFC6749Error(err).Error())
		})
	}
}

func TestParseRegistrationPolicyAcceptsGoTypedValues(t *testing.T) {
	policy, err := ParseRegistrationPolicy(map[string]any{
		consts.ClientMetadataGrantTypes:    map[string]any{policyRuleSubsetOf: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}},
		consts.ClientMetadataResponseTypes: map[string]any{policyRuleOneOf: []string{consts.ResponseTypeAuthorizationCodeFlow}},
		policyMemberMaxRegistrations:       int(1),
	}, nil, true)

	require.NoError(t, err)
	require.NotNil(t, policy)

	assert.Equal(t, int64(1), policy.MaxRegistrations())
	assert.Contains(t, policy.rules, "grant_types")
	assert.Contains(t, policy.rules, "response_types")
	assert.NotContains(t, policy.rules, policyMemberScope)
	assert.NotContains(t, policy.rules, "max_registrations")
}

func TestRegistrationPolicyAccessors(t *testing.T) {
	policy, err := ParseRegistrationPolicy(map[string]any{
		consts.ClientMetadataScope:   map[string]any{policyRulePattern: "a"},
		policyTestCustom:             map[string]any{policyRuleOneOf: []any{"x"}},
		policyMemberMaxRegistrations: 3,
	}, []string{policyTestCustom, policyMemberScope}, true)

	require.NoError(t, err)

	assert.Equal(t, int64(3), policy.MaxRegistrations())
	assert.True(t, policy.isCustom(policyTestCustom))
	assert.False(t, policy.isCustom(policyMemberScope))

	assert.Equal(t, map[string]any{
		consts.ClientMetadataScope: map[string]any{policyRulePattern: "a"},
		policyTestCustom:           map[string]any{policyRuleOneOf: []any{"x"}},
	}, policy.WithoutMaxRegistrations())

	unset, err := ParseRegistrationPolicy(map[string]any{}, nil, true)

	require.NoError(t, err)
	assert.Equal(t, int64(0), unset.MaxRegistrations())
	assert.Empty(t, unset.WithoutMaxRegistrations())
}

func TestRegistrationPolicyPatternIsAnchoredAlternation(t *testing.T) {
	policy, err := ParseRegistrationPolicy(map[string]any{consts.ClientMetadataScope: map[string]any{policyRulePattern: "a|b"}}, nil, true)
	require.NoError(t, err)

	assert.NoError(t, policy.Check(&oauth2.ClientRegistrationMetadata{Scope: "b"}))
	assert.NoError(t, policy.Check(&oauth2.ClientRegistrationMetadata{Scope: "a"}))

	err = policy.Check(&oauth2.ClientRegistrationMetadata{Scope: "ab"})
	require.Error(t, err)
	assert.Equal(t, policyErrorPrefix+"The 'scope' value 'ab' is not permitted by the registration policy.", oauth2.ErrorToDebugRFC6749Error(err).Error())
}

func TestRegistrationPolicyOmittedMembersClassified(t *testing.T) {
	none := []string{
		"redirect_uris", "client_name", "client_uri", "logo_uri", policyMemberScope, "contacts", "tos_uri", "policy_uri",
		policyMemberJWKS, "software_id", "software_statement", "software_version", "sector_identifier_uri",
		"userinfo_signed_response_alg", policyMemberDefaultMaxAge, "require_auth_time", "default_acr_values",
		"initiate_login_uri", "request_uris", "require_signed_request_object", "post_logout_redirect_uris",
		"backchannel_logout_uri", "backchannel_logout_session_required", "authorization_grant_profiles_supported",
		"tls_client_auth_subject_dn", "tls_client_auth_san_dns", "tls_client_auth_san_uri", "tls_client_auth_san_ip",
		"tls_client_auth_san_email", "tls_client_certificate_bound_access_tokens",
		"require_pushed_authorization_requests", "dpop_bound_access_tokens", "response_modes", "audience", "resource",
	}

	for _, member := range policyStandardMembers {
		_, omitted := policyOmittedMembers[member]

		assert.True(t, omitted != slices.Contains(none, member), "member '%s' must be classified exactly once", member)
	}

	for member := range policyOmittedMembers {
		assert.Contains(t, policyStandardMembers, member)
	}
}

func TestParseRegistrationPolicyPatternsNotPermitted(t *testing.T) {
	_, err := ParseRegistrationPolicy(map[string]any{
		consts.ClientMetadataGrantTypes: map[string]any{policyRuleSubsetOf: []any{consts.GrantTypeAuthorizationCode}},
		policyMemberRedirectURIs:        map[string]any{policyRulePattern: "https://.*"},
	}, nil, false)

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
	assert.Equal(t, policyErrorPrefix+"The registration policy member 'redirect_uris' rule 'pattern' is not permitted from the issuer of the presented Client Registration Token.", oauth2.ErrorToDebugRFC6749Error(err).Error())

	policy, err := ParseRegistrationPolicy(map[string]any{
		consts.ClientMetadataGrantTypes: map[string]any{policyRuleSubsetOf: []any{consts.GrantTypeAuthorizationCode}},
		policyMemberRedirectURIs:        map[string]any{policyRuleOneOf: []any{"https://example.com/cb"}},
	}, nil, false)

	require.NoError(t, err)
	assert.NoError(t, policy.Check(&oauth2.ClientRegistrationMetadata{RedirectURIs: []string{"https://example.com/cb"}}))
}
