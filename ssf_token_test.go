// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestGenerateSecurityEventToken(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	event := jwt.RawSecurityEvent{URI: "https://schemas.openid.net/secevent/risc/event-type/account-disabled", Claims: map[string]any{}}

	good := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	testCases := []struct {
		name    string
		config  *oauth2.SSFConfig
		stream  *oauth2.SSFStream
		subject *jwt.SubjectIdentifier
		event   jwt.SecurityEvent
		store   oauth2.Storage
		nostore bool
		err     string
	}{
		{name: "ShouldFailNilConfig", config: nil, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilStrategy", config: &oauth2.SSFConfig{}, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilStream", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailEmptyAudience", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com"}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailEmptyIssuer", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{ClientID: "rx-client", Audience: []string{"rx"}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilEvent", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: good, subject: subject, err: "server_error"},
		{name: "ShouldWrapStrategyError", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{err: errSSFSign}}, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldGenerate", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}}, stream: good, subject: subject, event: event},
		{name: "ShouldPassStreamOwner", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}}, stream: good, subject: subject, event: event},
		{name: "ShouldFailUnknownClient", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{ClientID: "other-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailEmptyClientID", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{Issuer: "https://tx.example.com", Audience: []string{"rx"}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilStore", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: good, subject: subject, event: event, nostore: true, err: "server_error"},
		{name: "ShouldFailNilClient", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: good, subject: subject, event: event, store: &ssfTestClientStore{MemoryStore: ssfTestStore()}, err: "server_error"},
		{name: "ShouldFailTypedNilClient", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: good, subject: subject, event: event, store: &ssfTestClientStore{MemoryStore: ssfTestStore(), client: (*oauth2.DefaultClient)(nil)}, err: "server_error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: tc.config}}

			switch {
			case tc.nostore:
				f.Store = nil
			case tc.store != nil:
				f.Store = tc.store
			}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), tc.stream, tc.subject, tc.event, "", "txn-1")

			if tc.err != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)
				assert.Empty(t, jti)

				if tc.name == "ShouldWrapStrategyError" {
					assert.ErrorIs(t, err, errSSFSign)

					return
				}

				if tc.config != nil && tc.config.TokenStrategy != nil {
					assert.Nil(t, tc.config.TokenStrategy.(*ssfTestStrategy).claims, "the strategy must not be called")
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.config.TokenStrategy.(*ssfTestStrategy).token, token)

			claims := tc.config.TokenStrategy.(*ssfTestStrategy).claims
			require.NotNil(t, claims)

			client := tc.config.TokenStrategy.(*ssfTestStrategy).client
			require.NotNil(t, client)
			assert.Equal(t, "rx-client", client.GetID())

			assert.Equal(t, "https://tx.example.com", claims.Issuer)
			assert.Equal(t, []string{"rx"}, claims.Audience)
			assert.Equal(t, "txn-1", claims.Transaction)
			assert.NotEmpty(t, jti)
			assert.Equal(t, claims.JTI, jti)
		})
	}
}

func TestGenerateSecurityEventTokenJTI(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	event := jwt.CAEPSessionRevoked{}
	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}
	strategy := &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}
	f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

	_, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "retry-1", "")
	require.NoError(t, err)
	assert.Equal(t, "retry-1", jti)
	assert.Equal(t, "retry-1", strategy.claims.JTI)

	_, first, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "", "")
	require.NoError(t, err)

	_, second, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "", "")
	require.NoError(t, err)

	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second)
}

func TestGenerateSecurityEventTokenType(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	testCases := []struct {
		name  string
		token string
		ok    bool
	}{
		{name: "ShouldAcceptExact", token: ssfTestToken("secevent+jwt"), ok: true},
		{name: "ShouldAcceptApplicationPrefix", token: ssfTestToken("application/secevent+jwt"), ok: true},
		{name: "ShouldAcceptOtherCase", token: ssfTestToken("SecEvent+JWT"), ok: true},
		{name: "ShouldRefuseJWT", token: ssfTestToken("JWT")},
		{name: "ShouldRefuseLogoutToken", token: ssfTestToken(jwt.JSONWebTokenTypeLogoutToken)},
		{name: "ShouldRefuseMissingType", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + ".e30.sig"},
		{name: "ShouldRefuseNonJSONHeader", token: base64.RawURLEncoding.EncodeToString([]byte(`nope`)) + ".e30.sig"},
		{name: "ShouldRefuseNonBase64Header", token: "!!.e30.sig"},
		{name: "ShouldRefuseEmpty", token: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: tc.token}}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.token, token)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
		})
	}
}

func TestGenerateSecurityEventTokenSigned(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	header := func(alg any) string {
		data, err := json.Marshal(map[string]any{"alg": alg, "typ": jwt.JSONWebTokenTypeSecurityEventToken})
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(data)
	}

	testCases := []struct {
		name  string
		token string
		ok    bool
	}{
		{name: "ShouldAcceptSigned", token: header("RS256") + ".e30.sig", ok: true},
		{name: "ShouldRefuseAlgNone", token: header("none") + ".e30."},
		{name: "ShouldRefuseAlgNoneWithSignature", token: header("none") + ".e30.sig"},
		{name: "ShouldRefuseAlgNoneOtherCase", token: header("NoNe") + ".e30.sig"},
		{name: "ShouldRefuseEmptyAlg", token: header("") + ".e30.sig"},
		{name: "ShouldRefuseAlgNotString", token: header(1) + ".e30.sig"},
		{name: "ShouldRefuseMissingAlg", token: base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"secevent+jwt"}`)) + ".e30.sig"},
		{name: "ShouldRefuseEmptySignature", token: header("RS256") + ".e30."},
		{name: "ShouldRefuseNoSignatureSegment", token: header("RS256") + ".e30"},
		{name: "ShouldRefuseHeaderOnly", token: header("RS256")},
		{name: "ShouldRefuseEmptyPayload", token: header("RS256") + "..sig"},
		{name: "ShouldRefusePayloadNotBase64URL", token: header("RS256") + ".e30!.sig"},
		{name: "ShouldRefusePayloadWithPadding", token: header("RS256") + ".e30=.sig"},
		{name: "ShouldRefuseSignatureNotBase64URL", token: header("RS256") + ".e30.s!g"},
		{name: "ShouldRefuseSignatureOfImpossibleLength", token: header("RS256") + ".e30.s"},
		{name: "ShouldRefuseSignatureInStandardAlphabet", token: header("RS256") + ".e30.s+/g"},
		{name: "ShouldRefuseFourSegments", token: header("RS256") + ".e30.sig.extra"},
		{name: "ShouldRefuseSignatureOfLineFeed", token: header("RS256") + ".e30.\n"},
		{name: "ShouldRefuseSignatureWithCarriageReturn", token: header("RS256") + ".e30.sig\r"},
		{name: "ShouldRefusePayloadWithLineFeed", token: header("RS256") + ".e\n30.sig"},
		{name: "ShouldRefuseHeaderWithLineFeed", token: header("RS256") + "\n.e30.sig"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: tc.token}}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.token, token)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
		})
	}
}

func TestGenerateSecurityEventTokenEncrypted(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keySig := &jose.JSONWebKey{Key: key, KeyID: "sig", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature}
	keyEnc := &jose.JSONWebKey{Key: &key.PublicKey, KeyID: "enc", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption}

	claims, err := jwt.NewSecurityEventTokenClaims(stream.Issuer, stream.Audience, subject, jwt.CAEPSessionRevoked{}, "")
	require.NoError(t, err)

	nested := func(headersJWE map[string]any) string {
		token, _, err := jwt.EncodeNestedCompactEncrypted(t.Context(), claims,
			&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}},
			&jwt.Headers{Extra: headersJWE}, keySig, keyEnc, jose.A256GCM)
		require.NoError(t, err)

		return token
	}

	header := func(header map[string]any) string {
		data, err := json.Marshal(header)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(data)
	}

	good := map[string]any{"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT"}

	with := func(key string, value any) map[string]any {
		out := map[string]any{}

		for k, v := range good {
			out[k] = v
		}

		if value == nil {
			delete(out, key)
		} else {
			out[key] = value
		}

		return out
	}

	testCases := []struct {
		name  string
		token string
		ok    bool
	}{
		{name: "ShouldAcceptNestedWithDefaultHeader", token: nested(nil), ok: true},
		{name: "ShouldAcceptNestedWithTypedHeader", token: nested(map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}), ok: true},
		{name: "ShouldAcceptNoType", token: header(good) + ".key.iv.ct.tag", ok: true},
		{name: "ShouldAcceptDirectEncryption", token: header(with("alg", "dir")) + "..iv.ct.tag", ok: true},
		{name: "ShouldAcceptContentTypeWithPrefix", token: header(with("cty", "application/jwt")) + ".key.iv.ct.tag", ok: true},
		{name: "ShouldRefuseOtherType", token: header(with("typ", jwt.JSONWebTokenTypeLogoutToken)) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseMissingContentType", token: header(with("cty", nil)) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseOtherContentType", token: header(with("cty", "json")) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseMissingEnc", token: header(with("enc", nil)) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseMissingAlg", token: header(with("alg", nil)) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseAlgNone", token: header(with("alg", "none")) + ".key.iv.ct.tag"},
		{name: "ShouldRefuseEmptyCiphertext", token: header(good) + ".key.iv..tag"},
		{name: "ShouldRefuseEmptyTag", token: header(good) + ".key.iv.ct."},
		{name: "ShouldRefuseEmptyIV", token: header(good) + ".key..ct.tag"},
		{name: "ShouldRefuseEncryptedKeyNotBase64URL", token: header(good) + ".k!y.iv.ct.tag"},
		{name: "ShouldRefuseIVNotBase64URL", token: header(good) + ".key.i!.ct.tag"},
		{name: "ShouldRefuseCiphertextNotBase64URL", token: header(good) + ".key.iv.c!.tag"},
		{name: "ShouldRefuseTagNotBase64URL", token: header(good) + ".key.iv.ct.t!g"},
		{name: "ShouldRefuseSixSegments", token: header(good) + ".key.iv.ct.tag.extra"},
		{name: "ShouldRefuseEncryptedKeyOfLineFeed", token: header(good) + ".\n.iv.ct.tag"},
		{name: "ShouldRefuseTagWithCarriageReturn", token: header(good) + ".key.iv.ct.tag\r"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: tc.token}}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.token, token)
				assert.NotEmpty(t, jti)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
		})
	}
}

func TestGenerateSecurityEventTokenRequiresEncryption(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	header, err := json.Marshal(map[string]string{"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT"})
	require.NoError(t, err)

	jws := ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)
	jwe := base64.RawURLEncoding.EncodeToString(header) + ".key.iv.ct.tag"

	client := func(alg string) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{ID: "rx-client"},

			SecurityEventTokenEncryptedResponseAlg: alg,
		}
	}

	testCases := []struct {
		name   string
		client oauth2.Client
		token  string
		ok     bool
	}{
		{name: "ShouldAcceptSignedForClientWithoutMetadata", client: &oauth2.DefaultClient{ID: "rx-client"}, token: jws, ok: true},
		{name: "ShouldAcceptSignedForClientWithoutEncryptionAlg", client: client(""), token: jws, ok: true},
		{name: "ShouldAcceptEncryptedForClientWithoutEncryptionAlg", client: client(""), token: jwe, ok: true},
		{name: "ShouldAcceptEncryptedForEncryptingClient", client: client(string(jose.RSA_OAEP_256)), token: jwe, ok: true},
		{name: "ShouldRefuseSignedForEncryptingClient", client: client(string(jose.RSA_OAEP_256)), token: jws},
		{name: "ShouldRefuseSignedForNoneAlgClient", client: client(jwt.JSONWebTokenAlgNone), token: jws},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &ssfTestStrategy{token: tc.token}

			f := &oauth2.Fosite{Store: &ssfTestClientStore{MemoryStore: ssfTestStore(), client: tc.client}, Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			require.NotNil(t, strategy.claims, "the strategy must be called")

			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.token, token)
				assert.NotEmpty(t, jti)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
		})
	}
}

func TestDefaultSecurityEventTokenStrategyRequiresEncryption(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyClient, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := &jwt.DefaultStrategy{
		Config: &oauth2.Config{},
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		}}),
	}

	client := func(alg string) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{ID: "rx"},
			JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: keyClient.Public(), KeyID: "rsa-1", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
			}},

			SecurityEventTokenEncryptedResponseAlg: alg,
		}
	}

	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		strategy jwt.Strategy
		client   oauth2.Client
		segments int
	}{
		{name: "ShouldSignWithSigningOnlyStrategyForClientWithoutEncryptionAlg", strategy: &ssfTestSigningOnlyStrategy{Strategy: issuer}, client: client(""), segments: 3},
		{name: "ShouldEncryptForEncryptingClient", strategy: issuer, client: client(string(jose.RSA_OAEP_256)), segments: 5},
		{name: "ShouldFailSigningOnlyStrategyForEncryptingClient", strategy: &ssfTestSigningOnlyStrategy{Strategy: issuer}, client: client(string(jose.RSA_OAEP_256))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := jwt.NewSecurityEventTokenClaims("https://tx.example.com", []string{"rx"}, subject, jwt.CAEPSessionRevoked{}, "")
			require.NoError(t, err)

			token, err := (&oauth2.DefaultSecurityEventTokenStrategy{Strategy: tc.strategy}).GenerateSecurityEventToken(t.Context(), tc.client, claims)

			if tc.segments == 0 {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)

				return
			}

			require.NoError(t, err)
			assert.Len(t, strings.Split(token, "."), tc.segments)
		})
	}
}

func TestGenerateSecurityEventTokenStreamSubject(t *testing.T) {
	stream := &oauth2.SSFStream{ClientID: "rx-client", StreamID: "stream-1", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	opaque := func(id string) *jwt.SubjectIdentifier {
		subject, err := jwt.NewSubjectIdentifierOpaque(id)
		require.NoError(t, err)

		return subject
	}

	email, err := jwt.NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	verification := jwt.SSFVerification{State: new("abc")}
	updated := jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused}

	testCases := []struct {
		name    string
		stream  *oauth2.SSFStream
		subject *jwt.SubjectIdentifier
		event   jwt.SecurityEvent
		ok      bool
	}{
		{name: "ShouldAcceptVerificationForStream", stream: stream, subject: opaque("stream-1"), event: verification, ok: true},
		{name: "ShouldAcceptVerificationPointerForStream", stream: stream, subject: opaque("stream-1"), event: &verification, ok: true},
		{name: "ShouldAcceptStreamUpdatedForStream", stream: stream, subject: opaque("stream-1"), event: updated, ok: true},
		{name: "ShouldAcceptRawVerificationForStream", stream: stream, subject: opaque("stream-1"), event: jwt.RawSecurityEvent{URI: jwt.SecurityEventTypeSSFVerification, Claims: map[string]any{}}, ok: true},
		{name: "ShouldRefuseVerificationForOtherStream", stream: stream, subject: opaque("stream-2"), event: verification},
		{name: "ShouldRefuseVerificationWithEmailSubject", stream: stream, subject: email, event: verification},
		{name: "ShouldRefuseVerificationWithoutSubject", stream: stream, event: verification},
		{name: "ShouldRefuseVerificationWithoutStreamID", stream: &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}, subject: opaque("stream-1"), event: verification},
		{name: "ShouldRefuseRawVerificationForOtherStream", stream: stream, subject: opaque("stream-2"), event: jwt.RawSecurityEvent{URI: jwt.SecurityEventTypeSSFVerification, Claims: map[string]any{}}},
		{name: "ShouldRefuseStreamUpdatedForOtherStream", stream: stream, subject: opaque("stream-2"), event: updated},
		{name: "ShouldRefuseStreamUpdatedWithEmailSubject", stream: stream, subject: email, event: updated},
		{name: "ShouldRefuseStreamUpdatedWithoutSubject", stream: stream, event: updated},
		{name: "ShouldRefuseRawStreamUpdatedForOtherStream", stream: stream, subject: opaque("stream-2"), event: jwt.RawSecurityEvent{URI: jwt.SecurityEventTypeSSFStreamUpdated, Claims: map[string]any{"status": "paused"}}},
		{name: "ShouldAcceptOtherEventWithOtherOpaqueSubject", stream: stream, subject: opaque("stream-2"), event: jwt.CAEPSessionRevoked{}, ok: true},
		{name: "ShouldAcceptOtherEventWithEmailSubject", stream: stream, subject: email, event: jwt.CAEPSessionRevoked{}, ok: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), tc.stream, tc.subject, tc.event, "", "")

			if tc.ok {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
				assert.NotEmpty(t, jti)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
			assert.Nil(t, strategy.claims, "the strategy must not be called")
		})
	}
}

func TestGenerateSecurityEventTokenCAEPInteroperabilityProfile(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := func(key any, alg jose.SignatureAlgorithm) oauth2.SecurityEventTokenStrategy {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: string(alg), Use: jwt.JSONWebTokenUseSignature}}}

		return &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{Config: &oauth2.Config{}, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks)}, SigningAlg: string(alg)}
	}

	fixed := func(alg string, signature []byte) oauth2.SecurityEventTokenStrategy {
		header, err := json.Marshal(map[string]string{"alg": alg, "typ": jwt.JSONWebTokenTypeSecurityEventToken})
		require.NoError(t, err)

		return &ssfTestStrategy{token: base64.RawURLEncoding.EncodeToString(header) + ".e30." + base64.RawURLEncoding.EncodeToString(signature)}
	}

	claims, err := jwt.NewSecurityEventTokenClaims(stream.Issuer, stream.Audience, subject, jwt.CAEPSessionRevoked{}, "")
	require.NoError(t, err)

	encrypted, _, err := jwt.EncodeNestedCompactEncrypted(t.Context(), claims,
		&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}}, nil,
		&jose.JSONWebKey{Key: rsa2048, KeyID: "sig", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		&jose.JSONWebKey{Key: &rsa2048.PublicKey, KeyID: "enc", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption}, jose.A256GCM)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		strategy  oauth2.SecurityEventTokenStrategy
		profile   bool
		malformed bool
	}{
		{name: "ShouldAcceptRS256With2048BitKey", strategy: signer(rsa2048, jose.RS256), profile: true},
		{name: "ShouldAcceptRS256With3072BitKey", strategy: signer(rsa3072, jose.RS256), profile: true},
		{name: "ShouldAcceptRS256WithSignatureOf256Bytes", strategy: fixed("RS256", make([]byte, 256)), profile: true},
		{name: "ShouldRefuseRS256WithSignatureOf255Bytes", strategy: fixed("RS256", make([]byte, 255))},
		{name: "ShouldRefuseRS256With1024BitKeySignature", strategy: fixed("RS256", make([]byte, 128))},
		{name: "ShouldRefuseRS256WithSignatureNotBase64URL", strategy: &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken) + "="}, malformed: true},
		{name: "ShouldRefuseES256", strategy: signer(ec256, jose.ES256)},
		{name: "ShouldRefusePS256", strategy: signer(rsa2048, jose.PS256)},
		{name: "ShouldRefuseRS384", strategy: signer(rsa2048, jose.RS384)},
		{name: "ShouldRefuseRS256OtherCase", strategy: fixed("rs256", make([]byte, 256))},
		{name: "ShouldRefuseEncrypted", strategy: &ssfTestStrategy{token: encrypted}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: tc.strategy, EnforceCAEPInteroperabilityProfile: true}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.profile {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
				assert.NotEmpty(t, jti)
			} else {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)
				assert.Empty(t, jti)
			}

			f = &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: tc.strategy}}}

			token, _, err = f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.malformed {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)

				return
			}

			require.NoError(t, err, "the profile is not enforced by default")
			assert.NotEmpty(t, token)
		})
	}
}

func TestGenerateSecurityEventTokenEncryptedWithProfile(t *testing.T) {
	keyIssuer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyClient, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	strategy := &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{
		Config: &oauth2.Config{},
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: keyIssuer, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		}}),
	}}

	store := storage.NewMemoryStore()

	store.Clients["rx-client"] = &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{ID: "rx-client"},
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: keyClient.Public(), KeyID: "rsa-1", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		}},

		SecurityEventTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
	}

	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	testCases := []struct {
		name    string
		profile bool
		err     bool
	}{
		{name: "ShouldEncryptWithoutProfile"},
		{name: "ShouldFailWithProfile", profile: true, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Store: store, Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy, EnforceCAEPInteroperabilityProfile: tc.profile}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.err {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)
				assert.Empty(t, jti)

				return
			}

			require.NoError(t, err)
			require.Len(t, strings.Split(token, "."), 5)

			jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A128CBC_HS256})
			require.NoError(t, err)

			plaintext, err := jwe.Decrypt(keyClient)
			require.NoError(t, err)

			decoded, err := jwt.Parse(string(plaintext), func(*jwt.Token) (any, error) { return keyIssuer.Public(), nil })
			require.NoError(t, err)

			assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, decoded.Header[jwt.JSONWebTokenHeaderType])
			assert.Equal(t, jti, decoded.Claims.ToMapClaims()[jwt.ClaimJWTID])
		})
	}
}

func TestDefaultSecurityEventTokenStrategy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature}}}
	strategy := &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{Config: &oauth2.Config{}, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks)}}

	f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

	subject, err := jwt.NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{InitiatingEntity: jwt.SecurityEventInitiatingEntityAdmin}}, "", "txn-1")
	require.NoError(t, err)

	decoded, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return key.Public(), nil })
	require.NoError(t, err)

	assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, decoded.Header[jwt.JSONWebTokenHeaderType])

	claims := decoded.Claims.ToMapClaims()

	assert.Equal(t, jti, claims[jwt.ClaimJWTID])
	assert.Equal(t, "txn-1", claims[jwt.ClaimTransaction])
	assert.Equal(t, "https://tx.example.com", claims[jwt.ClaimIssuer])
	assert.Equal(t, map[string]any{"format": "email", "email": "john@example.com"}, claims[jwt.ClaimSubjectIdentifier])

	events, ok := claims[jwt.ClaimEvents].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{"initiating_entity": "admin"}}, events)

	t.Run("ShouldFailWithoutStrategy", func(t *testing.T) {
		_, err := (&oauth2.DefaultSecurityEventTokenStrategy{}).GenerateSecurityEventToken(t.Context(), nil, &jwt.SecurityEventTokenClaims{})
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestDefaultSecurityEventTokenStrategyValidatesClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature}}}
	strategy := &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{Config: &oauth2.Config{}, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks)}}

	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	valid := func() *jwt.SecurityEventTokenClaims {
		claims, err := jwt.NewSecurityEventTokenClaims("https://tx.example.com", []string{"rx"}, subject, jwt.CAEPSessionRevoked{}, "")
		require.NoError(t, err)

		return claims
	}

	testCases := []struct {
		name   string
		claims func() *jwt.SecurityEventTokenClaims
		ok     bool
	}{
		{name: "ShouldSignValidClaims", claims: valid, ok: true},
		{name: "ShouldRefuseNilClaims", claims: func() *jwt.SecurityEventTokenClaims { return nil }},
		{name: "ShouldRefuseNoEvents", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.Events = map[string]any{}

			return claims
		}},
		{name: "ShouldRefuseTwoEvents", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.Events[jwt.SecurityEventTypeCAEPSessionEstablished] = map[string]any{}

			return claims
		}},
		{name: "ShouldRefuseEventPayloadNotObject", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.Events = map[string]any{"https://example.com/event": "abc"}

			return claims
		}},
		{name: "ShouldRefuseMissingIssuer", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.Issuer = ""

			return claims
		}},
		{name: "ShouldRefuseEmptyAudienceValue", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.Audience = []string{""}

			return claims
		}},
		{name: "ShouldRefuseMissingJTI", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.JTI = ""

			return claims
		}},
		{name: "ShouldRefuseMissingIssuedAt", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.IssuedAt = nil

			return claims
		}},
		{name: "ShouldRefuseInvalidSubject", claims: func() *jwt.SecurityEventTokenClaims {
			claims := valid()
			claims.SubjectIdentifier = &jwt.SubjectIdentifier{Format: "email"}

			return claims
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := strategy.GenerateSecurityEventToken(t.Context(), nil, tc.claims())

			if tc.ok {
				require.NoError(t, err)
				assert.NotEmpty(t, token)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
		})
	}
}

func TestConfigGetSSFConfig(t *testing.T) {
	assert.Nil(t, (&oauth2.Config{}).GetSSFConfig(t.Context()))

	c := (&oauth2.Config{SSF: &oauth2.SSFConfig{}}).GetSSFConfig(t.Context())
	require.NotNil(t, c)
	assert.Empty(t, c.Audience)
	assert.Equal(t, int64(1<<16), c.MaxRequestBytes)

	c = (&oauth2.Config{SSF: &oauth2.SSFConfig{Audience: "a", MaxRequestBytes: 10}}).GetSSFConfig(t.Context())
	assert.Equal(t, "a", c.Audience)
	assert.Equal(t, int64(10), c.MaxRequestBytes)
}

func TestGenerateSecurityEventTokenStoredIssuer(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	event := jwt.RawSecurityEvent{URI: "https://schemas.openid.net/secevent/risc/event-type/account-disabled", Claims: map[string]any{}}

	testCases := []struct {
		name     string
		stored   string
		config   string
		expected string
	}{
		{"ShouldUseConfiguredIssuerForHTTP", "http://old.example.com", "https://tx.example.com", "https://tx.example.com"},
		{"ShouldUseConfiguredIssuerForQuery", "https://old.example.com?x=1", "https://tx.example.com", "https://tx.example.com"},
		{"ShouldKeepValidStoredIssuer", "https://old.example.com", "https://tx.example.com", "https://old.example.com"},
		{"ShouldFailWithNoValidIssuer", "http://old.example.com", "http://tx.example.com", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}
			f := &oauth2.Fosite{Store: ssfTestStore(), Config: &oauth2.Config{Issuer: tc.config, SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}
			stream := &oauth2.SSFStream{ClientID: "rx-client", Issuer: tc.stored, Audience: []string{"rx"}}

			_, _, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "", "")

			assert.Equal(t, tc.stored, stream.Issuer)

			if tc.expected == "" {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Nil(t, strategy.claims)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, strategy.claims.Issuer)
		})
	}
}

var errSSFSign = errors.New("sign failed")

type ssfTestStrategy struct {
	client oauth2.Client
	claims *jwt.SecurityEventTokenClaims
	token  string
	err    error
}

func (s *ssfTestStrategy) GenerateSecurityEventToken(ctx context.Context, client oauth2.Client, claims *jwt.SecurityEventTokenClaims) (token string, err error) {
	s.client = client
	s.claims = claims

	return s.token, s.err
}

type ssfTestClientStore struct {
	*storage.MemoryStore

	client oauth2.Client
}

func (s *ssfTestClientStore) GetClient(context.Context, string) (client oauth2.Client, err error) {
	return s.client, nil
}

func ssfTestStore() *storage.MemoryStore {
	store := storage.NewMemoryStore()

	store.Clients["rx-client"] = &oauth2.DefaultClient{ID: "rx-client"}

	return store
}

func ssfTestToken(typ string) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ})

	return base64.RawURLEncoding.EncodeToString(header) + ".e30.sig"
}

type ssfTestSigningOnlyStrategy struct {
	jwt.Strategy
}

func (s *ssfTestSigningOnlyStrategy) Encode(ctx context.Context, claims jwt.Claims, _ ...jwt.StrategyOpt) (token, signature string, err error) {
	return s.Strategy.Encode(ctx, claims,
		jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}}),
		jwt.WithIssuerSigningAlg(string(jose.RS256)))
}
