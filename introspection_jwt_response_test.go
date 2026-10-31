// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestIntrospectionJWTResponseNegotiation(t *testing.T) {
	const (
		secret       = "foobarfoobarfoobarfoobarfoobar12"
		accept       = "application/token-introspection+jwt"
		contentJSON  = consts.ContentTypeApplicationJSON
		contentJWT   = consts.ContentTypeApplicationTokenIntrospectionJWT
		caller       = "rs"
		introspected = "active-token"
	)

	key := gen.MustRSAKey()

	testCases := []struct {
		name     string
		alg      string
		accept   string
		token    string
		noSigner bool
		content  string
		active   bool
		headerA  string
	}{
		{name: "ShouldReturnJSONWithoutARequestOrRegistration", token: introspected, content: contentJSON, active: true},
		{name: "ShouldReturnJSONForAnInactiveTokenWithoutARequestOrRegistration", token: "unknown", content: contentJSON},
		{name: "ShouldReturnAJWTForTheAcceptHeaderDefaultingToRS256", accept: accept, token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForAnAcceptListWithParameters", accept: "application/json;q=0.5, " + accept + ";q=1", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForARegisteredAlgorithm", alg: "RS256", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForARegisteredAlgorithmWhenJSONIsAccepted", alg: "RS256", accept: contentJSON, token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldSignAnInactiveResponseForTheAcceptHeader", accept: accept, token: "unknown", content: contentJWT, headerA: "RS256"},
		{name: "ShouldSignAnInactiveResponseForARegisteredAlgorithm", alg: "RS256", token: "unknown", content: contentJWT, headerA: "RS256"},
		{name: "ShouldNotTreatARefusedMediaTypeAsARequest", accept: accept + ";q=0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatARefusalWithADecimalZeroAsARequest", accept: accept + ";q=0.0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatARefusalWithALongDecimalZeroAsARequest", accept: accept + ";q=0.000", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatAnUppercaseRefusalAsARequest", accept: accept + ";Q=0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldTreatALowQualityAsARequest", accept: accept + ";q=0.001", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldTreatAMalformedQualityAsARequest", accept: accept + ";q=high", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnJSONForTheAcceptHeaderWithoutASigner", accept: accept, noSigner: true, token: introspected, content: contentJSON, active: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients[caller] = &DefaultRegisteredClient{
				DefaultClient:                  &DefaultClient{ID: caller, ClientSecret: NewPlainTextClientSecret(secret)},
				IntrospectionSignedResponseAlg: tc.alg,
			}

			config := &Config{
				IntrospectionIssuer:        "https://as.example.com",
				TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{token: introspected}},
			}

			if !tc.noSigner {
				config.IntrospectionJWTResponseStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
			}

			provider := &Fosite{Store: store, Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {tc.token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth(caller, secret)

			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			responder, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
			if err != nil {
				provider.WriteIntrospectionError(ctx, recorder, err)
			} else {
				provider.WriteIntrospectionResponse(ctx, recorder, responder)
			}

			require.Equal(t, http.StatusOK, recorder.Code)
			assert.Contains(t, recorder.Header().Get(consts.HeaderContentType), tc.content)

			var body map[string]any

			if tc.content == contentJSON {
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
				assert.Equal(t, tc.active, body["active"])

				return
			}

			signed, err := jose.ParseSigned(recorder.Body.String(), []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)
			require.Len(t, signed.Signatures, 1)

			assert.Equal(t, tc.headerA, signed.Signatures[0].Header.Algorithm)

			payload, err := signed.Verify(&key.PublicKey)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(payload, &body))

			// RFC 9701 Section 5.
			assert.Equal(t, "https://as.example.com", body[consts.ClaimIssuer])
			assert.NotEmpty(t, body[consts.ClaimIssuedAt])
			assert.Contains(t, body[consts.ClaimAudience], caller)

			introspection, ok := body["token_introspection"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tc.active, introspection["active"])

			if !tc.active {
				assert.Len(t, introspection, 1, "an inactive response MUST NOT include other members")
			}
		})
	}
}

func TestIntrospectionStrategyServerError(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobar12"

	testCases := []struct {
		name     string
		failure  error
		code     int
		contains string
	}{
		{name: "ShouldReportAServerError", failure: ErrServerError.WithDebug("the store failed"), code: http.StatusInternalServerError, contains: "server_error"},
		{name: "ShouldReportAWrappedServerError", failure: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: "server_error"},
		{name: "ShouldAnswerARejectionAsInactive", failure: ErrRequestUnauthorized, code: http.StatusOK, contains: `"active":false`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["rs"] = &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret(secret)}}

			provider := &Fosite{Store: store, Config: &Config{TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{failure: tc.failure}}}}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"token"}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth("rs", secret)

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			_, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
			require.Error(t, err)

			provider.WriteIntrospectionError(ctx, recorder, err)

			assert.Equal(t, tc.code, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tc.contains)
		})
	}
}

func TestIntrospectionServerErrorIsNotReportedAsInactive(t *testing.T) {
	recorder := httptest.NewRecorder()

	(&Fosite{Config: &Config{}}).WriteIntrospectionError(context.Background(), recorder, ErrServerError.WithHint("Failed to generate the response."))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), `"active"`)
	assert.Contains(t, recorder.Body.String(), "server_error")
}

type fixedIntrospector struct {
	token   string
	failure error
}

func (i *fixedIntrospector) IntrospectToken(_ context.Context, token string, _ TokenUse, request AccessRequester, _ []string) (TokenUse, error) {
	if i.failure != nil {
		return "", i.failure
	}

	if token != i.token {
		return "", ErrUnknownRequest
	}

	request.SetSession(&DefaultSession{Subject: "peter"})

	return AccessToken, nil
}
