// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAccessTokenFromRequest(t *testing.T) {
	testCases := []struct {
		name    string
		request func() *http.Request
		token   string
		dpop    bool
	}{
		{
			name: "DPoPScheme",
			request: func() *http.Request {
				r := &http.Request{Header: http.Header{}}
				r.Header.Set(consts.HeaderAuthorization, "DPoP dpop-token")
				return r
			},
			token: "dpop-token",
			dpop:  true,
		},
		{
			name: "DPoPSchemeCaseInsensitive",
			request: func() *http.Request {
				r := &http.Request{Header: http.Header{}}
				r.Header.Set(consts.HeaderAuthorization, "dpop dpop-token")
				return r
			},
			token: "dpop-token",
			dpop:  true,
		},
		{
			name: "BearerScheme",
			request: func() *http.Request {
				r := &http.Request{Header: http.Header{}}
				r.Header.Set(consts.HeaderAuthorization, "Bearer bearer-token")
				return r
			},
			token: "bearer-token",
			dpop:  false,
		},
		{
			name: "QueryParameterFallback",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://rs.example.com/userinfo?access_token=query-token", nil)
			},
			token: "query-token",
			dpop:  false,
		},
		{
			name: "FormBodyFallback",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "https://rs.example.com/userinfo", strings.NewReader("access_token=form-token"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			token: "form-token",
			dpop:  false,
		},
		{
			name: "None",
			request: func() *http.Request {
				return &http.Request{Header: http.Header{}}
			},
			token: "",
			dpop:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, dpop := AccessTokenFromRequest(tc.request())
			assert.Equal(t, tc.token, token)
			assert.Equal(t, tc.dpop, dpop)
		})
	}
}

func TestValidateResourceAccessHappyPath(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)
	token := "access-token-value"

	proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "ra-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
	})

	r := newResourceRequest(http.MethodPost, resourceURL, token, proof)

	parsed, err := s.ValidateResourceAccess(context.Background(), r, token, thumbprint(t, key), false)
	require.NoError(t, err)
	assert.Equal(t, thumbprint(t, key), parsed.Thumbprint)
}

func TestValidateResourceAccessRejects(t *testing.T) {
	token := "access-token-value"

	testCases := []struct {
		name      string
		request   func(t *testing.T, key *jose.JSONWebKey) *http.Request
		boundJKT  func(t *testing.T, key *jose.JSONWebKey) string
		wantErr   error
		wantHint  string
		wantDebug string
	}{
		{
			name: "EmptyBoundJKT",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
				})
				return newResourceRequest(http.MethodPost, resourceURL, token, proof)
			},
			boundJKT: func(t *testing.T, key *jose.JSONWebKey) string { return "" },
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The access token is not bound to a DPoP key.",
		},
		{
			name: "BearerDowngrade",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e2", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
				})
				r := newResourceRequest(http.MethodPost, resourceURL, "", proof)
				r.Header.Set(consts.HeaderAuthorization, "Bearer "+token)
				return r
			},
			wantErr:   oauth2.ErrInvalidDPoPProof,
			wantHint:  "The DPoP-bound access token was not presented using the DPoP authentication scheme.",
			wantDebug: "dpop scheme used: false, token matches: true",
		},
		{
			name: "PresentedTokenMismatch",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e3", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
				})
				return newResourceRequest(http.MethodPost, resourceURL, "some-other-token", proof)
			},
			wantErr:   oauth2.ErrInvalidDPoPProof,
			wantHint:  "The DPoP-bound access token was not presented using the DPoP authentication scheme.",
			wantDebug: "dpop scheme used: true, token matches: false",
		},
		{
			name: "MultipleDPoPHeaders",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e4", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
				})
				r := newResourceRequest(http.MethodPost, resourceURL, token, proof)
				r.Header.Add(consts.HeaderDPoP, proof)
				return r
			},
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The request contains more than one DPoP proof but only one is allowed.",
		},
		{
			name: "MissingProof",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				return newResourceRequest(http.MethodPost, resourceURL, token, "")
			},
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The request to the protected resource requires a DPoP proof but none was provided.",
		},
		{
			name: "MissingAth",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e5", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(),
				})
				return newResourceRequest(http.MethodPost, resourceURL, token, proof)
			},
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The DPoP proof is missing the required 'ath' claim.",
		},
		{
			name: "AthMismatch",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e6", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim("a-different-token"),
				})
				return newResourceRequest(http.MethodPost, resourceURL, token, proof)
			},
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The DPoP proof 'ath' claim does not match the access token.",
		},
		{
			name: "KeyMismatch",
			request: func(t *testing.T, key *jose.JSONWebKey) *http.Request {
				proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "e7", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
				})
				return newResourceRequest(http.MethodPost, resourceURL, token, proof)
			},
			boundJKT: func(t *testing.T, key *jose.JSONWebKey) string { return thumbprint(t, newTestProofKey(t)) },
			wantErr:  oauth2.ErrInvalidDPoPProof,
			wantHint: "The DPoP proof key does not match the key the access token is bound to.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStrategy()
			key := newTestProofKey(t)

			jkt := thumbprint(t, key)
			if tc.boundJKT != nil {
				jkt = tc.boundJKT(t, key)
			}

			_, err := s.ValidateResourceAccess(context.Background(), tc.request(t, key), token, jkt, false)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.wantHint, oauth2.ErrorToRFC6749Error(err).HintField)
			if tc.wantDebug != "" {
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).DebugField, tc.wantDebug)
			}
		})
	}
}

func TestValidateResourceAccessRequiresNonce(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)
	token := "access-token-value"

	proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "nonce-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: resourceURL, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": athClaim(token),
	})

	r := newResourceRequest(http.MethodPost, resourceURL, token, proof)

	_, err := s.ValidateResourceAccess(context.Background(), r, token, thumbprint(t, key), true)
	assert.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)
}

func athClaim(token string) string {
	sum := sha256.Sum256([]byte(token))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func thumbprint(t *testing.T, key *jose.JSONWebKey) string {
	t.Helper()

	jkt, err := jwt.ThumbprintJWK(key)
	require.NoError(t, err)

	return jkt
}

func newResourceRequest(method, rawURL, token, proof string) *http.Request {
	u, _ := url.Parse(rawURL)

	r := &http.Request{Method: method, Header: http.Header{}, URL: u, Host: u.Host}

	if u.Scheme == consts.SchemeHTTPS {
		r.Header.Set(consts.HeaderXForwardedProto, consts.SchemeHTTPS)
	}

	if token != "" {
		r.Header.Set(consts.HeaderAuthorization, "DPoP "+token)
	}

	if proof != "" {
		r.Header.Add(consts.HeaderDPoP, proof)
	}

	return r
}

const resourceURL = "https://rs.example.com/userinfo"
