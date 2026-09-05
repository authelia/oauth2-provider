// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jose"
	josejwt "authelia.com/provider/oauth2/token/jose/jwt"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestHandler_BindAccessRequest(t *testing.T) {
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	key := newTestProofKey(t)
	thumbprint := testProofThumbprint(t, key)

	proofWith := func(t *testing.T, id string, claims map[string]any) string {
		t.Helper()

		base := map[string]any{
			jwt.ClaimJWTID:      id,
			jwt.ClaimHTTPMethod: http.MethodPost,
			jwt.ClaimHTTPURI:    "https://as.example.com/token",
			jwt.ClaimIssuedAt:   time.Now().Unix(),
		}

		for k, v := range claims {
			base[k] = v
		}

		return signProof(t, key, jwt.JSONWebTokenTypeDPoP, base)
	}

	t.Run("ShouldRecordKeyWhenCodeHashMatches", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb1", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.NotEmpty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldNotRecordKeyWhenThumbprintAbsent", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb1a", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldNotRecordKeyWhenKeyBindingNotGranted", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		raw := proofWith(t, "kb-nogrant", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, raw), request))
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldRejectMismatchedCodeHash", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb2", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash("wrong")})

		err := handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request)

		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldRejectProofWithoutCodeHash", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		err := handler.BindAccessRequest(ctxWithPublishedProof(t, proofWith(t, "kb3", nil)), request)

		require.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof is missing the 'c_s256' claim, which is required because the 'bound_key' scope was granted.")
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldIgnoreWhenDisabled", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: false, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb4", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldIgnoreWhenDPoPDisabled", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: false}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb4a", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldRejectSessionWithoutKeyBindingSupport", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &thumbprintOnlySession{Session: &oauth2.DefaultSession{}}

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb6", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		err := handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request)

		assert.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "The session does not support DPoP key binding.")
	})

	t.Run("ShouldIgnoreSessionWithoutKeyBindingSupportWhenNoKeyBindingAttempted", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &thumbprintOnlySession{Session: &oauth2.DefaultSession{}}

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		proof := proofWith(t, "kb6a", nil)

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
	})

	t.Run("ShouldUseDeviceCodeForDeviceGrant", func(t *testing.T) {
		const deviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"

		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeOAuthDeviceCode}
		request.Form = url.Values{consts.FormParameterDeviceCode: []string{deviceCode}}

		proof := proofWith(t, "kb5", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(deviceCode)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.NotEmpty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldNotRecordKeyWhenNoThumbprintWasRequested", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		raw := proofWith(t, "kb-req-1", map[string]any{jwt.ClaimDPoPCodeHash: CodeHash(code)})

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, raw), request))
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldErrorWhenNoProofWasPublished", func(t *testing.T) {
		handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(thumbprint)
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint(thumbprint)

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		ctx := context.WithValue(t.Context(), oauth2.DPoPProofContextKey, &oauth2.DPoPProofHolder{})

		err := handler.BindAccessRequest(ctx, request)

		assert.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Empty(t, session.GetDPoPPublicKeyJWK())
	})
}

func TestHandler_BindAccessRequestRefreshNarrowing(t *testing.T) {
	newRefresh := func(scopes oauth2.Arguments) *oauth2.AccessRequest {
		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint("thumbprint")
		session.SetOIDCKeyBindingGranted(true)
		session.SetRequestedDPoPJWKThumbprint("thumbprint")
		session.SetDPoPPublicKeyJWK([]byte(`{"kty":"EC"}`))

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
		request.GrantedScope = scopes
		request.Form = url.Values{}

		return request
	}

	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	t.Run("ShouldNotRejectWhenBoundKeyDropped", func(t *testing.T) {
		request := newRefresh(oauth2.Arguments{consts.ScopeOpenID})

		require.NoError(t, handler.BindAccessRequest(t.Context(), request))
		assert.NotEmpty(t, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldNotRejectWhenBoundKeyNeverGranted", func(t *testing.T) {
		assert.NoError(t, handler.BindAccessRequest(t.Context(), newRefresh(nil)))
	})

	t.Run("ShouldAllowWhenBoundKeyRetained", func(t *testing.T) {
		assert.NoError(t, handler.BindAccessRequest(t.Context(), newRefresh(oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey})))
	})
}

func TestHandler_PopulateBoundTokenEndpointResponse(t *testing.T) {
	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	response := oauth2.NewAccessResponse()

	assert.NoError(t, handler.PopulateBoundTokenEndpointResponse(t.Context(), request, response))
}

func TestHandler_BindAccessRequestRejectsMismatchedProofKey(t *testing.T) {
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	key := newTestProofKey(t)

	proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID:        "mismatch-1",
		jwt.ClaimHTTPMethod:   http.MethodPost,
		jwt.ClaimHTTPURI:      "https://as.example.com/token",
		jwt.ClaimIssuedAt:     time.Now().Unix(),
		jwt.ClaimDPoPCodeHash: CodeHash(code),
	})

	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	session := &oauth2.DefaultSession{}
	session.SetOIDCKeyBindingGranted(true)
	session.SetRequestedDPoPJWKThumbprint("a-different-key-thumbprint-than-the-proof")
	session.SetDPoPJWKThumbprint(testProofThumbprint(t, key))

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
	request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

	err := handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	assert.Empty(t, session.GetDPoPPublicKeyJWK())
}

func TestHandler_BindAccessRequestLeavesNoKeyWhenValidationFails(t *testing.T) {
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	key := newTestProofKey(t)
	jkt := testProofThumbprint(t, key)

	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint(jkt)
	session.SetOIDCKeyBindingGranted(true)
	session.SetRequestedDPoPJWKThumbprint(jkt)

	newRequest := func() *oauth2.AccessRequest {
		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}
		request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

		return request
	}

	ctx := context.WithValue(t.Context(), oauth2.DPoPProofContextKey, &oauth2.DPoPProofHolder{})

	assert.ErrorIs(t, handler.BindAccessRequest(ctx, newRequest()), oauth2.ErrServerError)
	require.Empty(t, session.GetDPoPPublicKeyJWK(), "a rejected attempt must leave no key on the session")

	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "residual-2", jwt.ClaimHTTPMethod: http.MethodPost,
		jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	assert.ErrorIs(t, handler.BindAccessRequest(ctxWithPublishedProof(t, raw), newRequest()), oauth2.ErrInvalidDPoPProof)
	assert.Empty(t, session.GetDPoPPublicKeyJWK())
}

func TestHandler_BindAccessRequestRejectsAProofWithoutAKey(t *testing.T) {
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint("thumbprint")
	session.SetOIDCKeyBindingGranted(true)
	session.SetRequestedDPoPJWKThumbprint("thumbprint")

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
	request.Form = url.Values{consts.FormParameterAuthorizationCode: []string{code}}

	ctx := context.WithValue(t.Context(), oauth2.DPoPProofContextKey, &oauth2.DPoPProofHolder{})

	oauth2.PublishDPoPProof(ctx, &oauth2.DPoPProof{Thumbprint: "thumbprint", CodeHash: CodeHash(code)})

	var err error

	require.NotPanics(t, func() { err = handler.BindAccessRequest(ctx, request) })

	assert.ErrorIs(t, err, oauth2.ErrServerError)
	assert.Empty(t, session.GetDPoPPublicKeyJWK())
}

func TestHandler_BindAccessRequestReportsAnUnrecordedDPoPJKT(t *testing.T) {
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	key := newTestProofKey(t)

	proof := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID:        "unrecorded-1",
		jwt.ClaimHTTPMethod:   http.MethodPost,
		jwt.ClaimHTTPURI:      "https://as.example.com/token",
		jwt.ClaimIssuedAt:     time.Now().Unix(),
		jwt.ClaimDPoPCodeHash: CodeHash(code),
	})

	handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	newRequest := func(granted bool, grant, parameter string) *oauth2.AccessRequest {
		session := &oauth2.DefaultSession{}
		session.SetOIDCKeyBindingGranted(granted)
		session.SetDPoPJWKThumbprint(testProofThumbprint(t, key))

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}
		request.GrantTypes = oauth2.Arguments{grant}
		request.Form = url.Values{parameter: []string{code}}

		return request
	}

	t.Run("ShouldRejectTheAuthorizationCodeGrant", func(t *testing.T) {
		request := newRequest(true, consts.GrantTypeAuthorizationCode, consts.FormParameterAuthorizationCode)

		err := handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request)

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "dpop_jkt")
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "DPoPAuthorizeFactory")
		assert.Empty(t, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPPublicKeyJWK())
	})

	t.Run("ShouldRejectTheDeviceCodeGrant", func(t *testing.T) {
		request := newRequest(true, consts.GrantTypeOAuthDeviceCode, consts.FormParameterDeviceCode)

		err := handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request)

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "DPoPDeviceAuthorizeFactory")
		assert.Empty(t, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPPublicKeyJWK())
	})

	// Section 2.3: without the marker this is a plain RFC 9449 client whose authentication request carried no
	// 'dpop_jkt', which must be accepted and left unbound rather than reported as a fault.
	t.Run("ShouldAcceptAGrantThatWasNotGrantedBoundKey", func(t *testing.T) {
		request := newRequest(false, consts.GrantTypeAuthorizationCode, consts.FormParameterAuthorizationCode)

		require.NoError(t, handler.BindAccessRequest(ctxWithPublishedProof(t, proof), request))
		assert.Empty(t, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPPublicKeyJWK())
	})
}

type thumbprintOnlySession struct {
	oauth2.Session

	thumbprint string
}

func (s *thumbprintOnlySession) SetDPoPJWKThumbprint(thumbprint string) {
	s.thumbprint = thumbprint
}

func (s *thumbprintOnlySession) GetDPoPJWKThumbprint() (thumbprint string) {
	return s.thumbprint
}

func newTestProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
}

func testProofThumbprint(t *testing.T, key *jose.JSONWebKey) (jkt string) {
	t.Helper()

	pub := key.Public()

	jkt, err := jwt.ThumbprintJWK(&pub)
	require.NoError(t, err)

	return jkt
}

func signProof(t *testing.T, key *jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(typ)),
	)
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func ctxWithPublishedProof(t *testing.T, raw string) context.Context {
	t.Helper()

	proof, err := rfc9449.ParseProof(raw, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	ctx := context.WithValue(t.Context(), oauth2.DPoPProofContextKey, &oauth2.DPoPProofHolder{})

	oauth2.PublishDPoPProof(ctx, proof)

	return ctx
}
