// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"fmt"
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
		build   func() (*SubjectIdentifier, error)
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
			build:   func() (*SubjectIdentifier, error) { return NewSubjectIdentifierEmail("") },
			wantErr: "email",
		},
		{
			name:    "ShouldRejectMissingIssuer",
			build:   func() (*SubjectIdentifier, error) { return NewSubjectIdentifierIssuerSubject("", "b") },
			wantErr: "iss",
		},
		{
			name:    "ShouldRejectMissingSubject",
			build:   func() (*SubjectIdentifier, error) { return NewSubjectIdentifierIssuerSubject("https://a", "") },
			wantErr: "sub",
		},
		{
			name:    "ShouldRejectEmptyOpaque",
			build:   func() (*SubjectIdentifier, error) { return NewSubjectIdentifierOpaque("") },
			wantErr: "id",
		},
		{
			name: "ShouldRejectEmptyComplex",
			build: func() (*SubjectIdentifier, error) {
				return NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{})
			},
			wantErr: "complex",
		},
		{
			name: "ShouldRejectInvalidComplexMember",
			build: func() (*SubjectIdentifier, error) {
				return NewSubjectIdentifierComplex(SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatEmail}})
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
			name: "ShouldRejectComplexInsideAliases",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{
					Format:                          SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: email()},
				}}}
			},
			wantErr: "must not be a complex subject",
		},
		{
			name: "ShouldRejectComplexInsideAliasesAfterSimple",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email(), {
					Format:                          SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{Tenant: &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "t"}},
				}}}
			},
			wantErr: "must not be a complex subject",
		},
		{
			name: "ShouldRejectComplexInsideAliasesInsideComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{
					Format: SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{
						Format:                          SubjectIdentifierFormatComplex,
						SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: email()},
					}}}},
				}
			},
			wantErr: "must not be a complex subject",
		},
		{
			name: "ShouldRejectAliasesNestedThroughComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{
					Format:                          SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email()}}},
				}}}
			},
			wantErr: "must not be a complex subject",
		},
		{
			name: "ShouldEncodeAliasesInsideComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{
					Format:                          SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email()}}},
				}
			},
			want: `{"format":"complex","user":{"format":"aliases","identifiers":[{"format":"email","email":"user@example.com"}]}}`,
		},
		{
			name: "ShouldRejectComplexMemberOfComplex",
			have: func(t *testing.T) *SubjectIdentifier {
				return &SubjectIdentifier{
					Format: SubjectIdentifierFormatComplex,
					SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{
						Format:                          SubjectIdentifierFormatComplex,
						SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: email()},
					}},
				}
			},
			wantErr: "must not be a complex subject",
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
			if tc.build != nil {
				s, err := tc.build()
				assert.Nil(t, s)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			s := tc.have(t)

			if tc.wantErr != "" {
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

func TestSubjectIdentifierMemberValues(t *testing.T) {
	email := func(v string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: v}
	}

	phone := func(v string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatPhoneNumber, PhoneNumber: v}
	}

	account := func(v string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatAccount, URI: v}
	}

	did := func(v string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatDID, URL: v}
	}

	uri := func(v string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatURI, URI: v}
	}

	issSub := func(iss, sub string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatIssuerSubject, Issuer: iss, Subject: sub}
	}

	jwtID := func(iss, jti string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatJWTID, Issuer: iss, JWTID: jti}
	}

	ips := func(v ...string) *SubjectIdentifier {
		return &SubjectIdentifier{Format: SubjectIdentifierFormatIPAddresses, IPAddresses: v}
	}

	aliases := func(v ...*SubjectIdentifier) *SubjectIdentifier {
		s := &SubjectIdentifier{Format: SubjectIdentifierFormatAliases}

		for _, identifier := range v {
			s.Identifiers = append(s.Identifiers, *identifier)
		}

		return s
	}

	testCases := []struct {
		name    string
		have    *SubjectIdentifier
		wantErr string
	}{
		{"ShouldAcceptEmail", email("user@example.com"), ""},
		{"ShouldAcceptEmailWithTag", email("user+tag@mail.example.com"), ""},
		{"ShouldAcceptEmailQuotedLocalPart", email(`"john doe"@example.com`), ""},
		{"ShouldAcceptEmailQuotedLocalPartThatNeedsNoQuotes", email(`"john.doe"@example.com`), ""},
		{"ShouldAcceptEmailQuotedLocalPartWithQuotedPair", email(`"john\"doe"@example.com`), ""},
		{"ShouldAcceptEmailDomainLiteral", email("user@[192.0.2.1]"), ""},
		{"ShouldRejectEmailLeadingSpace", email(" user@example.com"), "'email'"},
		{"ShouldRejectEmailQuotedAngleAddr", email(`<"john.doe"@example.com>`), "'email'"},
		{"ShouldRejectEmailQuotedDisplayName", email(`"John" <user@example.com>`), "'email'"},
		{"ShouldRejectEmailClosingAngle", email("a@example.com> <b@example.com"), "'email'"},
		{"ShouldRejectEmailWithoutDomain", email("notanemail"), "'email'"},
		{"ShouldRejectEmailEmptyDomain", email("a@"), "'email'"},
		{"ShouldRejectEmailEmptyLocalPart", email("@b"), "'email'"},
		{"ShouldRejectEmailUnquotedSpace", email("a b@c"), "'email'"},
		{"ShouldRejectEmailTwoAt", email("a@b@c"), "'email'"},
		{"ShouldRejectEmailBlank", email(" "), "'email'"},
		{"ShouldRejectEmailSurroundingSpace", email(" user@example.com "), "'email'"},
		{"ShouldRejectEmailDisplayName", email("John <user@example.com>"), "'email'"},
		{"ShouldRejectEmailAngleAddr", email("<user@example.com>"), "'email'"},
		{"ShouldRejectEmailComment", email("user@example.com (John)"), "'email'"},
		{"ShouldRejectEmailList", email("a@example.com, b@example.com"), "'email'"},

		{"ShouldAcceptPhoneNumber", phone("+12065550100"), ""},
		{"ShouldAcceptPhoneNumberMaximumLength", phone("+123456789012345"), ""},
		{"ShouldRejectPhoneNumberWithoutPrefix", phone("12065550100"), "'phone_number'"},
		{"ShouldRejectPhoneNumberWords", phone("not-a-phone"), "'phone_number'"},
		{"ShouldRejectPhoneNumberCountryCodeOnly", phone("+1"), "'phone_number'"},
		{"ShouldRejectPhoneNumberLeadingZero", phone("+0123456789"), "'phone_number'"},
		{"ShouldRejectPhoneNumberTooLong", phone("+1234567890123456"), "'phone_number'"},
		{"ShouldRejectPhoneNumberSeparators", phone("+1 206 555 0100"), "'phone_number'"},
		{"ShouldRejectPhoneNumberBlank", phone(" "), "'phone_number'"},

		{"ShouldAcceptAccount", account("acct:example.user@service.example.com"), ""},
		{"ShouldAcceptAccountEncodedUserPart", account("acct:juliet%40capulet.example@shoppingsite.example.com"), ""},
		{"ShouldRejectAccountOtherScheme", account("https://x"), "'uri'"},
		{"ShouldRejectAccountMailto", account("mailto:a@b"), "'uri'"},
		{"ShouldRejectAccountSchemeOnly", account("acct:"), "'uri'"},
		{"ShouldRejectAccountWithoutHost", account("acct:user"), "'uri'"},
		{"ShouldRejectAccountEmptyHost", account("acct:user@"), "'uri'"},
		{"ShouldRejectAccountEmptyUserPart", account("acct:@example.com"), "'uri'"},
		{"ShouldRejectAccountSpace", account("acct:a b@example.com"), "'uri'"},
		{"ShouldRejectAccountBadEscape", account("acct:a%zz@example.com"), "'uri'"},
		{"ShouldRejectAccountBlank", account(" "), "'uri'"},

		{"ShouldAcceptDID", did("did:example:123456"), ""},
		{"ShouldAcceptDIDColonSeparatedID", did("did:web:example.com:user:alice"), ""},
		{"ShouldAcceptDIDURL", did("did:example:123456/did/url/path?versionId=1#key-1"), ""},
		{"ShouldRejectDIDOtherScheme", did("https://x"), "'url'"},
		{"ShouldRejectDIDSchemeOnly", did("did:"), "'url'"},
		{"ShouldRejectDIDWithoutID", did("did:example"), "'url'"},
		{"ShouldRejectDIDEmptyID", did("did:example:"), "'url'"},
		{"ShouldRejectDIDUppercaseScheme", did("DID:example:1"), "'url'"},
		{"ShouldRejectDIDUppercaseMethod", did("did:Example:1"), "'url'"},
		{"ShouldRejectDIDSpace", did("did:example:1 2"), "'url'"},
		{"ShouldRejectDIDBlank", did(" "), "'url'"},

		{"ShouldAcceptURI", uri("https://user.example.com/"), ""},
		{"ShouldAcceptURIURN", uri("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66"), ""},
		{"ShouldAcceptURIIPv6Host", uri("https://[2001:db8::1]/path?query#fragment"), ""},
		{"ShouldAcceptURIIPv6HostWithPort", uri("https://user@[2001:db8::1]:8443"), ""},
		{"ShouldAcceptURIIPv6HostWithZone", uri("https://[fe80::1%25eth0]/"), ""},
		{"ShouldAcceptURIAuthorityWithEmptyPath", uri("https://user.example.com"), ""},
		{"ShouldAcceptURIPortAndQuery", uri("https://user.example.com:8443/a/b?c=d&e=/?"), ""},
		{"ShouldAcceptURIEmptyAuthority", uri("file:///etc/hosts"), ""},
		{"ShouldAcceptURIRootlessPath", uri("mailto:user@example.com"), ""},
		{"ShouldRejectURIBracketInPath", uri("https://user.example.com/a[b]"), "'uri'"},
		{"ShouldRejectURIBracketInQuery", uri("https://user.example.com/?a[]=b"), "'uri'"},
		{"ShouldRejectURIBracketInPathAfterIPv6Host", uri("https://[2001:db8::1]/a[b]"), "'uri'"},
		{"ShouldRejectURIBracketInUserInfo", uri("https://a[b]@user.example.com/"), "'uri'"},
		{"ShouldRejectURIBracketInRootlessPath", uri("urn:example:a[b]"), "'uri'"},
		{"ShouldRejectURIBracketInRegisteredName", uri("https://user[1].example.com/"), "'uri'"},
		{"ShouldRejectURIUnclosedIPv6Host", uri("https://[2001:db8::1/"), "'uri'"},
		{"ShouldRejectURIWithoutScheme", uri("notauri"), "'uri'"},
		{"ShouldRejectURISpace", uri("has space:x y"), "'uri'"},
		{"ShouldRejectURIColons", uri("::::"), "'uri'"},
		{"ShouldRejectURIRelative", uri("/path"), "'uri'"},
		{"ShouldRejectURIBlank", uri(" "), "'uri'"},

		{"ShouldAcceptIssuerSubject", issSub("https://issuer.example.com/", "145234573"), ""},
		{"ShouldAcceptIssuerSubjectStrings", issSub("issuer", "subject with spaces"), ""},
		{"ShouldAcceptIssuerSubjectURISubject", issSub("https://issuer.example.com", "urn:example:user:1"), ""},
		{"ShouldRejectIssuerSubjectIssuerNotURI", issSub("a:b c", "x"), "'iss'"},
		{"ShouldRejectIssuerSubjectSubjectNotURI", issSub("https://issuer.example.com", "x:y z"), "'sub'"},

		{"ShouldAcceptJWTID", jwtID("https://idp.example.com/123456789/", "B70BA622-9515-4353-A866-823539EECBC8"), ""},
		{"ShouldAcceptJWTIDStringIssuer", jwtID("idp", "x"), ""},
		{"ShouldRejectJWTIDIssuerNotURI", jwtID("a:b c", "x"), "'iss'"},

		{"ShouldAcceptIPAddresses", ips("10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334", "::1"), ""},
		{"ShouldAcceptIPAddressNumericZone", ips("fe80::1%4"), ""},
		{"ShouldRejectIPAddressNamedZone", ips("fe80::1%eth0"), "'ip-addresses'"},
		{"ShouldRejectIPAddressPrefix", ips("10.0.0.0/8"), "'ip-addresses'"},
		{"ShouldRejectIPAddressPort", ips("10.0.0.1:80"), "'ip-addresses'"},
		{"ShouldRejectIPAddressEmpty", ips(""), "'ip-addresses'"},

		{"ShouldAcceptAliasesSameFormat", aliases(email("a@example.com"), email("b@example.com")), ""},
		{"ShouldAcceptAliasesSameValueOtherFormat", aliases(account("acct:a@example.com"), uri("acct:a@example.com")), ""},
		{"ShouldRejectAliasesDuplicate", aliases(email("a@example.com"), phone("+12065550100"), email("a@example.com")), "duplicate"},
		{"ShouldRejectAliasesDuplicateIgnoringForeignMembers", aliases(email("a@example.com"), &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "a@example.com", ID: "x"}), "duplicate"},
		{"ShouldRejectAliasesInvalidValue", aliases(email("a@example.com"), phone("555")), "'phone_number'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.Validate()

			if tc.wantErr == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrInvalidSubjectIdentifier)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestSubjectIdentifierUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected *SubjectIdentifier
		invalid  bool
	}{
		{"ShouldDecodeEmail", `{"format":"email","email":"user@example.com"}`, &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "user@example.com"}, false},
		{"ShouldDecodeMembersInAnyOrder", `{"sub":"1234","iss":"https://issuer.example.com","format":"iss_sub"}`, &SubjectIdentifier{Format: SubjectIdentifierFormatIssuerSubject, Issuer: "https://issuer.example.com", Subject: "1234"}, false},
		{"ShouldDecodeJWTID", `{"format":"jwt_id","iss":"https://issuer.example.com","jti":"x"}`, &SubjectIdentifier{Format: SubjectIdentifierFormatJWTID, Issuer: "https://issuer.example.com", JWTID: "x"}, false},
		{"ShouldDecodeIPAddresses", `{"format":"ip-addresses","ip-addresses":["192.0.2.1"]}`, &SubjectIdentifier{Format: SubjectIdentifierFormatIPAddresses, IPAddresses: []string{"192.0.2.1"}}, false},
		{"ShouldDecodeAliases", `{"format":"aliases","identifiers":[{"format":"opaque","id":"x"}]}`, &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{{Format: SubjectIdentifierFormatOpaque, ID: "x"}}}, false},
		{"ShouldDecodeComplex", `{"format":"complex","user":{"format":"opaque","id":"u"},"org_unit":{"format":"opaque","id":"o"}}`, &SubjectIdentifier{Format: SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "u"}, OrgUnit: &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "o"}}}, false},
		{"ShouldDecodeUnknownFormatForValidate", `{"format":"custom","value":"x"}`, &SubjectIdentifier{Format: "custom"}, true},
		{"ShouldDecodeMissingFormatForValidate", `{"email":"user@example.com"}`, &SubjectIdentifier{Email: "user@example.com"}, true},
		{"ShouldDecodeCaseFoldedFormatAsMissing", `{"FORMAT":"email","EMAIL":"user@example.com"}`, &SubjectIdentifier{}, true},
		{"ShouldRejectMemberOfOtherFormat", `{"format":"email","email":"user@example.com","id":"x"}`, nil, false},
		{"ShouldRejectUndefinedMember", `{"format":"email","email":"user@example.com","extra":true}`, nil, false},
		{"ShouldRejectCaseFoldedMember", `{"format":"email","EMAIL":"user@example.com"}`, nil, false},
		{"ShouldRejectDuplicateMember", `{"format":"email","email":"a@example.com","email":"b@example.com"}`, nil, false},
		{"ShouldRejectDuplicateFormat", `{"format":"opaque","format":"email","email":"a@example.com"}`, nil, false},
		{"ShouldRejectComplexMemberOnSimpleFormat", `{"format":"opaque","id":"x","user":{"format":"opaque","id":"u"}}`, nil, false},
		{"ShouldRejectForeignMemberInComplexMember", `{"format":"complex","user":{"format":"opaque","id":"u","email":"user@example.com"}}`, nil, false},
		{"ShouldRejectForeignMemberInAlias", `{"format":"aliases","identifiers":[{"format":"opaque","id":"x","email":"user@example.com"}]}`, nil, false},
		{"ShouldRejectDuplicateMemberInAlias", `{"format":"aliases","identifiers":[{"format":"opaque","id":"x","id":"y"}]}`, nil, false},
		{"ShouldRejectNumberMember", `{"format":"email","email":5}`, nil, false},
		{"ShouldRejectNumberFormat", `{"format":5}`, nil, false},
		{"ShouldRejectString", `"email"`, nil, false},
		{"ShouldRejectArray", `[]`, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual SubjectIdentifier

			err := json.Unmarshal([]byte(tc.have), &actual)

			if tc.expected == nil {
				assert.ErrorIs(t, err, ErrInvalidSubjectIdentifier)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, *tc.expected, actual)

			if tc.invalid {
				assert.ErrorIs(t, actual.Validate(), ErrInvalidSubjectIdentifier)
			} else {
				assert.NoError(t, actual.Validate())
			}
		})
	}

	t.Run("ShouldRejectForeignMemberInSecurityEventToken", func(t *testing.T) {
		const format = `{"iss":"iss","aud":["aud"],"jti":"id","iat":1700000000,"sub_id":%s,"events":{"urn:example:event":{}}}`

		var claims SecurityEventTokenClaims

		require.NoError(t, json.Unmarshal(fmt.Appendf(nil, format, `{"format":"opaque","id":"x"}`), &claims))
		require.NoError(t, claims.Valid())

		assert.Error(t, json.Unmarshal(fmt.Appendf(nil, format, `{"format":"opaque","id":"x","email":"user@example.com"}`), &claims))
		assert.Error(t, json.Unmarshal(fmt.Appendf(nil, format, `{"format":"opaque","ID":"x"}`), &claims))
	})
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
