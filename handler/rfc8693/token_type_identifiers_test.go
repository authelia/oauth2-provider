// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/storage"
)

func TestTokenTypeIdentifiersAreReservedFromClientIdentifierURLs(t *testing.T) {
	const id = "https://as.example.com/jwt"

	testCases := []struct {
		name      string
		tokenType oauth2.RFC8693TokenType
	}{
		{"ShouldRefuseTheIssueIssuer", &JWTType{Name: "urn:example:jwt", Issue: &JWTIssueConfig{Issuer: id}}},
		{"ShouldRefuseTheValidateIssuer", &JWTType{Name: "urn:example:jwt", Validate: &JWTValidationConfig{Issuer: id}}},
		{"ShouldRefuseTheTransactionTokenIssuer", &TxnTokenType{Name: "urn:example:txn", Issuer: id, TrustDomain: "trust.example.com"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &documentResolver{}

			config := &oauth2.Config{
				AuthorizationServerIdentificationIssuer: "https://as.example.com",
				ClientIDMetadataDocumentResolver:        resolver,
				RFC8693TokenTypes:                       map[string]oauth2.RFC8693TokenType{tc.tokenType.GetName(t.Context()): tc.tokenType},
			}

			client, err := oauth2.GetClient(t.Context(), config, storage.NewMemoryStore(), id)

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Nil(t, client)
			assert.Equal(t, 0, resolver.calls)
		})
	}
}

func TestTokenTypeIdentifiers(t *testing.T) {
	testCases := []struct {
		name      string
		tokenType oauth2.RFC8693TokenTypeIdentifiersProvider
		expected  []string
	}{
		{"ShouldReturnTheIssueAndValidateIssuers", &JWTType{Issue: &JWTIssueConfig{Issuer: "https://as.example.com/jwt"}, Validate: &JWTValidationConfig{Issuer: "https://idp.example.com"}}, []string{"https://as.example.com/jwt", "https://idp.example.com"}},
		{"ShouldReturnTheIssueIssuer", &JWTType{Issue: &JWTIssueConfig{Issuer: "https://as.example.com/jwt"}}, []string{"https://as.example.com/jwt"}},
		{"ShouldReturnTheValidateIssuer", &JWTType{Validate: &JWTValidationConfig{Issuer: "https://idp.example.com"}}, []string{"https://idp.example.com"}},
		{"ShouldReturnNothingForATypeWithoutRoles", &JWTType{}, nil},
		{"ShouldReturnNothingForANilJWTType", (*JWTType)(nil), nil},
		{"ShouldReturnTheTransactionTokenIssuerAndTrustDomain", &TxnTokenType{Issuer: "https://tts.example.com", TrustDomain: "trust.example.com"}, []string{"https://tts.example.com", "trust.example.com"}},
		{"ShouldReturnNothingForANilTransactionTokenType", (*TxnTokenType)(nil), nil},
		{"ShouldReturnTheSelfSignedIdentifier", &SelfSignedTokenType{Identifier: "https://tts.example.com"}, []string{"https://tts.example.com"}},
		{"ShouldReturnNothingForANilSelfSignedType", (*SelfSignedTokenType)(nil), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.tokenType.GetIdentifiers(t.Context()))
		})
	}
}
