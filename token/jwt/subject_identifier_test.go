// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2/token/jwt"
)

func mustSubject(t *testing.T, s *SubjectIdentifier, err error) *SubjectIdentifier {
	t.Helper()

	require.NoError(t, err)
	require.NotNil(t, s)

	return s
}

func TestSubjectIdentifier(t *testing.T) {
	email := func() *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "user@example.com"}
	}

	testCases := []struct {
		name    string
		have    func(t *testing.T) *SubjectIdentifier
		want    string
		wantErr string
	}{
		{
			name: "ShouldEncodeEmail",
			have: func(t *testing.T) *SubjectIdentifier {
				s, err := NewSubjectIdentifierEmail("user@example.com")
				return mustSubject(t, s, err)
			},
			want: `{"format":"email","email":"user@example.com"}`,
		},
		{
			name: "ShouldEncodeIssuerSubject",
			have: func(t *testing.T) *SubjectIdentifier {
				s, err := NewSubjectIdentifierIssuerSubject("https://a", "b")
				return mustSubject(t, s, err)
			},
			want: `{"format":"iss_sub","iss":"https://a","sub":"b"}`,
		},
		{
			name: "ShouldEncodeOpaque",
			have: func(t *testing.T) *SubjectIdentifier {
				s, err := NewSubjectIdentifierOpaque("11112222333344445555")
				return mustSubject(t, s, err)
			},
			want: `{"format":"opaque","id":"11112222333344445555"}`,
		},
		{
			name: "ShouldEncodeComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				tenant, err := NewSubjectIdentifierIssuerSubject("https://example.com/idp1", "1234")
				require.NoError(t, err)

				s, err := NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{User: email(), Tenant: tenant})

				return mustSubject(t, s, err)
			},
			want: `{"format":"complex","user":{"format":"email","email":"user@example.com"},"tenant":{"format":"iss_sub","iss":"https://example.com/idp1","sub":"1234"}}`,
		},
		{
			name: "ShouldEncodePhoneNumber",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatPhoneNumber, PhoneNumber: "+12065550100"}
			},
			want: `{"format":"phone_number","phone_number":"+12065550100"}`,
		},
		{
			name: "ShouldEncodeAccount",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAccount, URI: "acct:example.user@service.example.com"}
			},
			want: `{"format":"account","uri":"acct:example.user@service.example.com"}`,
		},
		{
			name: "ShouldEncodeDID",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatDID, URL: "did:example:123456"}
			},
			want: `{"format":"did","url":"did:example:123456"}`,
		},
		{
			name: "ShouldEncodeURI",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatURI, URI: "https://user.example.com/"}
			},
			want: `{"format":"uri","uri":"https://user.example.com/"}`,
		},
		{
			name: "ShouldEncodeAliases",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email(), {Format: SubjectIdentifierFormatPhoneNumber, PhoneNumber: "+12065550100"}}}
			},
			want: `{"format":"aliases","identifiers":[{"format":"email","email":"user@example.com"},{"format":"phone_number","phone_number":"+12065550100"}]}`,
		},
		{
			name: "ShouldEncodeJWTID",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatJWTID, Issuer: "https://idp.example.com/123456789/", JWTID: "B70BA622-9515-4353-A866-823539EECBC8"}
			},
			want: `{"format":"jwt_id","iss":"https://idp.example.com/123456789/","jti":"B70BA622-9515-4353-A866-823539EECBC8"}`,
		},
		{
			name: "ShouldEncodeSAMLAssertionID",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatSAMLAssertionID, SAMLIssuer: "https://idp.example.com/123456789/", AssertionID: "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"}
			},
			want: `{"format":"saml_assertion_id","issuer":"https://idp.example.com/123456789/","assertion_id":"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"}`,
		},
		{
			name: "ShouldEncodeIPAddresses",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatIPAddresses, IPAddresses: []string{"10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334"}}
			},
			want: `{"format":"ip-addresses","ip-addresses":["10.29.37.75","2001:0db8:0000:0000:0000:8a2e:0370:7334"]}`,
		},
		{
			name:    "ShouldRejectEmptyEmail",
			have:    func(t *testing.T) *SubjectIdentifier { s, _ := NewSubjectIdentifierEmail(""); return s },
			wantErr: "email",
		},
		{
			name:    "ShouldRejectMissingIssuer",
			have:    func(t *testing.T) *SubjectIdentifier { s, _ := NewSubjectIdentifierIssuerSubject("", "b"); return s },
			wantErr: "iss",
		},
		{
			name: "ShouldRejectMissingSubject",
			have: func(t *testing.T) *SubjectIdentifier {
				s, _ := NewSubjectIdentifierIssuerSubject("https://a", "")
				return s
			},
			wantErr: "sub",
		},
		{
			name:    "ShouldRejectEmptyOpaque",
			have:    func(t *testing.T) *SubjectIdentifier { s, _ := NewSubjectIdentifierOpaque(""); return s },
			wantErr: "id",
		},
		{
			name: "ShouldRejectEmptyComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				s, _ := NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{})
				return s
			},
			wantErr: "complex",
		},
		{
			name: "ShouldRejectInvalidComplexMember",
			have: func(t *testing.T) *SubjectIdentifier {
				s, _ := NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatEmail}})
				return s
			},
			wantErr: "user",
		},
		{
			name:    "ShouldRejectMissingFormat",
			have:    func(t *testing.T) *SubjectIdentifier { return &SubjectIdentifier{Email: "a@b"} },
			wantErr: "format",
		},
		{
			name:    "ShouldRejectUnknownFormat",
			have:    func(t *testing.T) *SubjectIdentifier { return &SubjectIdentifier{Format: "nope"} },
			wantErr: "format",
		},
		{
			name: "ShouldRejectEmptyPhoneNumber",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatPhoneNumber}
			},
			wantErr: "phone_number",
		},
		{
			name: "ShouldRejectEmptyAccountURI",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAccount}
			},
			wantErr: "uri",
		},
		{
			name:    "ShouldRejectEmptyDIDURL",
			have:    func(t *testing.T) *SubjectIdentifier { return &SubjectIdentifier{Format: SubjectIdentifierFormatDID} },
			wantErr: "url",
		},
		{
			name:    "ShouldRejectEmptyURI",
			have:    func(t *testing.T) *SubjectIdentifier { return &SubjectIdentifier{Format: SubjectIdentifierFormatURI} },
			wantErr: "uri",
		},
		{
			name: "ShouldRejectEmptyAliases",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases}
			},
			wantErr: "identifiers",
		},
		{
			name: "ShouldRejectNestedAliases",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email()}}}}
			},
			wantErr: "nested",
		},
		{
			name: "ShouldRejectInvalidAlias",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{Format: SubjectIdentifierFormatEmail}}}
			},
			wantErr: "email",
		},
		{
			name: "ShouldRejectJWTIDMissingIssuer",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatJWTID, JWTID: "x"}
			},
			wantErr: "iss",
		},
		{
			name: "ShouldRejectJWTIDMissingJTI",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatJWTID, Issuer: "x"}
			},
			wantErr: "jti",
		},
		{
			name: "ShouldRejectSAMLMissingIssuer",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatSAMLAssertionID, AssertionID: "x"}
			},
			wantErr: "issuer",
		},
		{
			name: "ShouldRejectSAMLMissingAssertionID",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatSAMLAssertionID, SAMLIssuer: "x"}
			},
			wantErr: "assertion_id",
		},
		{
			name: "ShouldRejectEmptyIPAddresses",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatIPAddresses}
			},
			wantErr: "ip-addresses",
		},
		{
			name: "ShouldRejectInvalidIPAddress",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatIPAddresses, IPAddresses: []string{"not-an-ip"}}
			},
			wantErr: "ip-addresses",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.have(t)

			if tc.wantErr != "" {
				if s == nil {
					return
				}

				err := s.Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, s.Validate())

			actual, err := json.Marshal(s)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(actual))

			var decoded SubjectIdentifier

			require.NoError(t, json.Unmarshal(actual, &decoded))
			assert.Equal(t, *s, decoded)
		})
	}
}

func TestSubjectIdentifierConstructorErrors(t *testing.T) {
	s, err := NewSubjectIdentifierEmail("")
	assert.Nil(t, s)
	assert.Error(t, err)

	s, err = NewSubjectIdentifierIssuerSubject("", "")
	assert.Nil(t, s)
	assert.Error(t, err)

	s, err = NewSubjectIdentifierOpaque("")
	assert.Nil(t, s)
	assert.Error(t, err)

	s, err = NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{})
	assert.Nil(t, s)
	assert.Error(t, err)
}

func TestSubjectIdentifierMarshalOnlyFormatMembers(t *testing.T) {
	full := SubjectIdentifier{
		Email:       "a@example.com",
		Issuer:      "https://iss.example.com",
		Subject:     "sub",
		ID:          "id",
		PhoneNumber: "+15555550100",
		URI:         "acct:a@example.com",
		URL:         "did:example:1",
		Identifiers: []SubjectIdentifier{{Format: SubjectIdentifierFormatOpaque, ID: "x", Email: "inner@example.com"}},
		JWTID:       "jti",
		SAMLIssuer:  "https://saml.example.com",
		AssertionID: "assertion",
		IPAddresses: []string{"192.0.2.1"},
		SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{
			User: &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "u", Email: "inner@example.com"},
		},
	}

	testCases := []struct {
		format   string
		expected string
	}{
		{SubjectIdentifierFormatEmail, `{"format":"email","email":"a@example.com"}`},
		{SubjectIdentifierFormatIssuerSubject, `{"format":"iss_sub","iss":"https://iss.example.com","sub":"sub"}`},
		{SubjectIdentifierFormatOpaque, `{"format":"opaque","id":"id"}`},
		{SubjectIdentifierFormatPhoneNumber, `{"format":"phone_number","phone_number":"+15555550100"}`},
		{SubjectIdentifierFormatAccount, `{"format":"account","uri":"acct:a@example.com"}`},
		{SubjectIdentifierFormatURI, `{"format":"uri","uri":"acct:a@example.com"}`},
		{SubjectIdentifierFormatDID, `{"format":"did","url":"did:example:1"}`},
		{SubjectIdentifierFormatAliases, `{"format":"aliases","identifiers":[{"format":"opaque","id":"x"}]}`},
		{SubjectIdentifierFormatComplex, `{"format":"complex","user":{"format":"opaque","id":"u"}}`},
		{SubjectIdentifierFormatJWTID, `{"format":"jwt_id","iss":"https://iss.example.com","jti":"jti"}`},
		{SubjectIdentifierFormatSAMLAssertionID, `{"format":"saml_assertion_id","issuer":"https://saml.example.com","assertion_id":"assertion"}`},
		{SubjectIdentifierFormatIPAddresses, `{"format":"ip-addresses","ip-addresses":["192.0.2.1"]}`},
		{"unknown", `{"format":"unknown"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.format, func(t *testing.T) {
			s := full
			s.Format = tc.format

			data, err := json.Marshal(s)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))

			data, err = json.Marshal(&s)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))
		})
	}

	t.Run("ShouldDropForeignMemberInSignedClaims", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("iss", []string{"aud"}, &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "id", Email: "leak@example.com"}, CAEPSessionRevoked{}, "")
		require.NoError(t, err)

		data, err := json.Marshal(claims.ToMap())
		require.NoError(t, err)
		assert.NotContains(t, string(data), "leak@example.com")
	})
}
