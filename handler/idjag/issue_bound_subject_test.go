// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	boundEndpoint = "https://idp.example.com/token"
	boundType     = "urn:bound:jwt"
	boundIssuer   = "https://assertions.example.com"
	boundClient   = "bound-client"
	boundSecret   = "foobarfoobarfoobarfoobarfoobar12"
)

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.11.1.1
func TestIssueHandlerWithABoundCustomJWTSubject(t *testing.T) {
	signing := gen.MustRSAKey()

	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		return key
	}

	thumbprint := func(key *ecdsa.PrivateKey) string {
		jkt, err := jwt.ThumbprintJWK(&jose.JSONWebKey{Key: &key.PublicKey})
		require.NoError(t, err)

		return jkt
	}

	holder, other := newKey(), newKey()
	certificate := gen.MustCertificate(gen.CertificateOptions{})

	testCases := []struct {
		name     string
		dpop     bool
		mtls     bool
		cnf      map[string]any
		proof    *ecdsa.PrivateKey
		cert     *x509.Certificate
		code     string
		member   string
		expected string
	}{
		{name: "ShouldRefuseABoundSubjectWithoutAProof", dpop: true, cnf: map[string]any{jwt.ClaimConfirmationJWKThumbprint: thumbprint(holder)}, code: "invalid_dpop_proof"},
		{name: "ShouldRefuseABoundSubjectWithAnotherKey", dpop: true, cnf: map[string]any{jwt.ClaimConfirmationJWKThumbprint: thumbprint(holder)}, proof: other, code: "invalid_dpop_proof"},
		{name: "ShouldBindToTheKeyOfABoundSubject", dpop: true, cnf: map[string]any{jwt.ClaimConfirmationJWKThumbprint: thumbprint(holder)}, proof: holder, expected: thumbprint(holder)},
		{name: "ShouldBindAnUnboundSubjectToTheProofKey", dpop: true, proof: other, expected: thumbprint(other)},
		{name: "ShouldNotBindWithoutAProof", dpop: true},
		{name: "ShouldRefuseABoundSubjectWhenDPoPIsDisabled", cnf: map[string]any{jwt.ClaimConfirmationJWKThumbprint: thumbprint(holder)}, proof: holder, code: "invalid_request"},
		{name: "ShouldRefuseACertificateBoundSubjectWithoutTheCertificate", mtls: true, cnf: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: oauth2.X509CertificateSHA256Thumbprint(certificate)}, code: "invalid_request"},
		// Section 9.11.2.1.
		{name: "ShouldBindToTheCertificateOfABoundSubject", mtls: true, cnf: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: oauth2.X509CertificateSHA256Thumbprint(certificate)}, cert: certificate, member: consts.ClaimConfirmationX509SHA256Thumbprint, expected: oauth2.X509CertificateSHA256Thumbprint(certificate)},
		// Section 9.11: a single binding, with the DPoP key preferred.
		{name: "ShouldBindOnlyToTheDPoPKeyOfASubjectBoundToACertificate", dpop: true, mtls: true, cnf: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: oauth2.X509CertificateSHA256Thumbprint(certificate)}, cert: certificate, proof: holder, expected: thumbprint(holder)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewExampleStore()
			store.Clients[boundClient] = &oauth2.DefaultClient{
				ID:           boundClient,
				ClientSecret: oauth2.NewPlainTextClientSecret(boundSecret),
				GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
				Scopes:       []string{redeemRead},
				Audience:     []string{redeemAudience},
			}
			store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: boundClient, Audience: redeemAudience}] = oauth2.IDJAGRelationship{
				Issuer:   redeemAudience,
				ClientID: redeemClient,
				Scopes:   []string{redeemRead},
			}
			store.IDJAGAudienceSubjects[storage.IDJAGAudienceSubjectKey{Issuer: redeemAudience, Subject: issueSubject}] = issueMapped

			config := &oauth2.Config{
				GlobalSecret:                            []byte("super-duper-secret-that-is-at-least-32-bytes"),
				RFC7591ClientRegistrationGlobalSecret:   []byte("a-completely-different-secret-at-least-32b"),
				AuthorizationServerIdentificationIssuer: redeemIssuer,
				DPoPEnabled:                             tc.dpop,
				MTLSEnabled:                             tc.mtls,
				RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693IDJAG: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
					boundType: &rfc8693.JWTType{
						Name:   boundType,
						Issuer: boundIssuer,
						JWTValidationConfig: rfc8693.JWTValidationConfig{
							ValidateFunc: jwt.Keyfunc(func(*jwt.Token) (any, error) { return &signing.PublicKey, nil }),
						},
					},
				},
			}

			claims := map[string]any{
				consts.ClaimIssuer:         boundIssuer,
				consts.ClaimSubject:        issueSubject,
				"subject":                  issueSubject,
				consts.ClaimAudience:       []string{boundClient},
				consts.ClaimExpirationTime: time.Now().Add(30 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			if tc.cnf != nil {
				claims[consts.ClaimConfirmation] = tc.cnf
			}

			form := url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectToken:       {signBound(t, signing, jose.RS256, "JWT", false, claims)},
				consts.FormParameterSubjectTokenType:   {boundType},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
				consts.FormParameterAudience:           {redeemAudience},
				consts.FormParameterScope:              {redeemRead},
			}

			r := httptest.NewRequest(http.MethodPost, boundEndpoint, strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.Header.Set(consts.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(boundClient+":"+boundSecret)))

			if tc.proof != nil {
				r.Header.Set("DPoP", signBound(t, tc.proof, jose.ES256, "dpop+jwt", true, map[string]any{
					"jti": strconv.FormatInt(time.Now().UnixNano(), 10),
					"htm": http.MethodPost,
					"htu": boundEndpoint,
					"iat": time.Now().Unix(),
				}))
			}

			if tc.cert != nil {
				r.TLS.PeerCertificates = []*x509.Certificate{tc.cert}
			}

			ctx := context.Background()
			provider := compose.ComposeAllEnabled(config, store, signing)

			request, err := provider.NewAccessRequest(ctx, r, rfc8693.NewDefaultSession())

			if tc.code != "" {
				assert.Equal(t, tc.code, oauth2.ErrorToRFC6749Error(err).ErrorField)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			response, err := provider.NewAccessResponse(ctx, request)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			issued, err := jose.ParseSigned(response.GetAccessToken(), []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)

			var result map[string]any

			require.NoError(t, json.Unmarshal(issued.UnsafePayloadWithoutVerification(), &result))

			if tc.expected == "" {
				assert.NotContains(t, result, consts.ClaimConfirmation)

				return
			}

			member := tc.member
			if member == "" {
				member = consts.ClaimConfirmationJWKThumbprint
			}

			assert.Equal(t, map[string]any{member: tc.expected}, result[consts.ClaimConfirmation])
		})
	}
}

func signBound(t *testing.T, key any, alg jose.SignatureAlgorithm, typ string, embed bool, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{EmbedJWK: embed}).WithType(jose.ContentType(typ)))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}
