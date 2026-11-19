// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testAudience      = "https://rp.example.com"
	testSignatureKID  = "sig-1"
	testEncryptionKID = "enc-1"
	testAgreementKID  = "enc-2"
	testJTI           = "jti-756E69717565"
	testTypeSET       = "secevent+jwt"
)

var (
	testEncryptionKey = sync.OnceValue(gen.MustRSAKey)
	testAgreementKey  = sync.OnceValue(gen.MustES256Key)
)

// testTransmitter is a Transmitter with one ES256 signing key, and a Receiver holding one RSA decryption key.
type testTransmitter struct {
	server   *testKeyServer
	receiver *Receiver
	record   *StreamRecord
	key      *ecdsa.PrivateKey
	now      time.Time
}

func newTestTransmitter(t *testing.T) *testTransmitter {
	x := &testTransmitter{key: gen.MustES256Key(), now: time.Unix(1700000000, 0).UTC()}

	x.server = newTestKeyServer(t, jose.JSONWebKey{Key: &x.key.PublicKey, KeyID: testSignatureKID, Use: "sig", Algorithm: string(jose.ES256)})
	x.receiver, _ = x.server.receiver()

	x.receiver.metadata.now = func() time.Time { return x.now }
	x.receiver.Config.Strategy = &jwt.DefaultStrategy{
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: testEncryptionKey(), KeyID: testEncryptionKID, Use: "enc", Algorithm: string(jose.RSA_OAEP_256)},
			{Key: testAgreementKey(), KeyID: testAgreementKID, Use: "enc", Algorithm: string(jose.ECDH_ES)},
		}}),
	}

	x.record = &StreamRecord{
		Issuer:          x.server.URL,
		StreamID:        "s1",
		Audience:        []string{testAudience},
		EventsDelivered: []string{jwt.SecurityEventTypeCAEPSessionRevoked},
		State:           StreamRecordActive,
	}

	return x
}

func (x *testTransmitter) claims() map[string]any {
	return map[string]any{
		"iss":    x.server.URL,
		"aud":    testAudience,
		"iat":    x.now.Unix(),
		"jti":    testJTI,
		"sub_id": map[string]any{"format": "email", "email": "user@example.com"},
		"events": map[string]any{
			jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": x.now.Unix(), "vendor_member": "kept"},
		},
	}
}

type testSET struct {
	typ string
	kid string
	alg jose.SignatureAlgorithm
	key any
}

func (x *testTransmitter) set() testSET {
	return testSET{typ: testTypeSET, kid: testSignatureKID, alg: jose.ES256, key: x.key}
}

func (s testSET) sign(t *testing.T, claims map[string]any) string {
	options := &jose.SignerOptions{}

	if s.typ != "" {
		options.WithType(jose.ContentType(s.typ))
	}

	if s.kid != "" {
		options.WithHeader("kid", s.kid)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, options)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signature, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signature.CompactSerialize()
	require.NoError(t, err)

	return token
}

func testEncrypt(t *testing.T, signed string, recipient jose.Recipient, headers map[jose.HeaderKey]any) string {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, &jose.EncrypterOptions{ExtraHeaders: headers})
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte(signed))
	require.NoError(t, err)

	token, err := encrypted.CompactSerialize()
	require.NoError(t, err)

	return token
}

func testRecipient(kid string) jose.Recipient {
	return jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &testEncryptionKey().PublicKey, KeyID: kid}
}

func testNestedHeaders() map[jose.HeaderKey]any {
	return map[jose.HeaderKey]any{"typ": "JWT", "cty": "JWT"}
}

func testUnsigned(t *testing.T, claims map[string]any) string {
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": testTypeSET, "kid": testSignatureKID})
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// testUnverifiedStrategy decodes without verifying the signature, as the strategy does for an 'alg' of 'none'.
type testUnverifiedStrategy struct {
	jwt.Strategy
}

func (s testUnverifiedStrategy) Decode(ctx context.Context, tokenString string, opts ...jwt.StrategyOpt) (*jwt.Token, error) {
	return s.Strategy.Decode(ctx, tokenString, append(opts, jwt.WithAllowUnverified())...)
}

func TestReceiverValidate(t *testing.T) {
	t.Run("ShouldAcceptSignedSET", func(t *testing.T) {
		x := newTestTransmitter(t)

		token := x.set().sign(t, x.claims())

		event, serr, err := x.receiver.validate(t.Context(), x.record, token)
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, event.Type)
		assert.Equal(t, &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{EventTimestamp: x.now.Unix()}}, event.Event)
		assert.Equal(t, "kept", event.Payload["vendor_member"])
		assert.Equal(t, testJTI, event.Claims.JTI)
		assert.Equal(t, x.server.URL, event.Claims.Issuer)
		assert.Equal(t, "user@example.com", event.Claims.SubjectIdentifier.Email)
		assert.Equal(t, token, event.Token)
		assert.False(t, event.Encrypted)
		assert.Nil(t, event.Principal)

		// The record of the event is a clone.
		require.NotSame(t, x.record, event.Stream)
		assert.Equal(t, x.record, event.Stream)

		event.Stream.Audience[0] = "changed"

		assert.Equal(t, testAudience, x.record.Audience[0])
	})

	t.Run("ShouldAcceptUnregisteredEventAsRaw", func(t *testing.T) {
		x := newTestTransmitter(t)

		claims := x.claims()
		claims["events"] = map[string]any{"https://vendor.example.com/event": map[string]any{"n": 1}}

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
		require.NoError(t, err)
		require.Nil(t, serr)

		assert.Equal(t, "https://vendor.example.com/event", event.Type)
		assert.IsType(t, jwt.RawSecurityEvent{}, event.Event)
	})

	t.Run("ShouldAcceptEveryDefaultAlgorithm", func(t *testing.T) {
		assert.Equal(t,
			[]jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA},
			(&Receiver{}).signingAlgs())
	})

	t.Run("ShouldNeverAllowSymmetricOrNoneAlgorithm", func(t *testing.T) {
		receiver := &Receiver{Config: Config{SigningAlgs: []string{"none", "HS256", "ES256", "HS512"}}}

		assert.Equal(t, []jose.SignatureAlgorithm{jose.ES256}, receiver.signingAlgs())
	})

	t.Run("ShouldDefaultClockSkew", func(t *testing.T) {
		assert.Equal(t, DefaultClockSkew, (&Receiver{}).clockSkew())
		assert.Equal(t, time.Duration(0), (&Receiver{Config: Config{ClockSkew: -1}}).clockSkew())
		assert.Equal(t, time.Minute, (&Receiver{Config: Config{ClockSkew: time.Minute}}).clockSkew())
	})

	// One case per SET error of the failure table, by its 'err' value.
	rejections := []struct {
		name     string
		expected *SetError
		token    func(t *testing.T, x *testTransmitter) string
	}{
		{
			"ShouldRejectNotCompactJWT", errSetNotCompact,
			func(t *testing.T, x *testTransmitter) string { return `{"iss":"` + x.server.URL + `"}` },
		},
		{
			"ShouldRejectEmptyToken", errSetNotCompact,
			func(t *testing.T, x *testTransmitter) string { return "" },
		},
		{
			"ShouldRejectMalformedHeader", errSetMalformed,
			func(t *testing.T, x *testTransmitter) string { return "bm90LWpzb24.e30.c2ln" },
		},
		{
			"ShouldRejectWrongTyp", errSetHeader,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.typ = "JWT"

				return set.sign(t, x.claims())
			},
		},
		{
			"ShouldRejectMissingTyp", errSetHeader,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.typ = ""

				return set.sign(t, x.claims())
			},
		},
		{
			"ShouldRejectSubClaim", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["sub"] = "user"

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectExpClaim", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["exp"] = x.now.Add(time.Hour).Unix()

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectMissingIAT", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				delete(claims, "iat")

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectMissingJTI", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				delete(claims, "jti")

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectMissingSubID", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				delete(claims, "sub_id")

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectNoEvent", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["events"] = map[string]any{}

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectMoreThanOneEvent", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["events"] = map[string]any{
					jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{},
					"https://vendor.example.com/event":      map[string]any{},
				}

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectInvalidPayloadOfKnownType", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["events"] = map[string]any{jwt.SecurityEventTypeCAEPCredentialChange: map[string]any{"change_type": "explode"}}

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectIssuedAtInTheFuture", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["iat"] = x.now.Add(DefaultClockSkew + 2*time.Second).Unix()

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectJTIThatIsNotAString", errSetClaims,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["jti"] = 7

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectAlgorithmNotAllowed", errSetSigningAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				x.receiver.Config.SigningAlgs = []string{"RS256"}

				return x.set().sign(t, x.claims())
			},
		},
		{
			"ShouldRejectUnknownKID", errSetSigningKey,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.kid = "sig-0"

				return set.sign(t, x.claims())
			},
		},
		{
			"ShouldRejectWithoutDecryptionKey", errSetDecryptionKey,
			func(t *testing.T, x *testTransmitter) string {
				return testEncrypt(t, x.set().sign(t, x.claims()), testRecipient("enc-0"), testNestedHeaders())
			},
		},
		{
			"ShouldRejectAlgNone", errSetSigningAlgorithm,
			func(t *testing.T, x *testTransmitter) string { return testUnsigned(t, x.claims()) },
		},
		{
			"ShouldRejectAlgNoneWhenConfigured", errSetSigningAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				x.receiver.Config.SigningAlgs = []string{"none", "ES256"}

				return testUnsigned(t, x.claims())
			},
		},
		{
			"ShouldRejectHS256SignedWithPublicKey", errSetSigningAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				x.receiver.Config.SigningAlgs = []string{"HS256", "ES256"}

				secret, err := x509.MarshalPKIXPublicKey(&x.key.PublicKey)
				require.NoError(t, err)

				set := x.set()
				set.alg, set.key = jose.HS256, secret

				return set.sign(t, x.claims())
			},
		},
		{
			"ShouldRejectSymmetricJWE", errSetKeyAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				recipient := jose.Recipient{Algorithm: jose.A256KW, Key: make([]byte, 32), KeyID: testEncryptionKID}

				return testEncrypt(t, x.set().sign(t, x.claims()), recipient, testNestedHeaders())
			},
		},
		{
			"ShouldRejectDirectJWE", errSetKeyAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				recipient := jose.Recipient{Algorithm: jose.DIRECT, Key: make([]byte, 32), KeyID: testEncryptionKID}

				return testEncrypt(t, x.set().sign(t, x.claims()), recipient, testNestedHeaders())
			},
		},
		{
			"ShouldRejectRSA15JWE", errSetKeyAlgorithm,
			func(t *testing.T, x *testTransmitter) string {
				recipient := jose.Recipient{Algorithm: jose.RSA1_5, Key: &testEncryptionKey().PublicKey, KeyID: testEncryptionKID}

				return testEncrypt(t, x.set().sign(t, x.claims()), recipient, testNestedHeaders())
			},
		},
		{
			"ShouldRejectJWENestingJWE", errSetNotDecrypted,
			func(t *testing.T, x *testTransmitter) string {
				nested := testEncrypt(t, x.set().sign(t, x.claims()), testRecipient(testEncryptionKID), testNestedHeaders())

				return testEncrypt(t, nested, testRecipient(testEncryptionKID), testNestedHeaders())
			},
		},
		{
			"ShouldRejectInvalidSignature", errSetSignature,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.key = gen.MustES256Key()

				return set.sign(t, x.claims())
			},
		},
		{
			"ShouldRejectInvalidSignatureOfNestedSET", errSetSignature,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.key = gen.MustES256Key()

				return testEncrypt(t, set.sign(t, x.claims()), testRecipient(testEncryptionKID), testNestedHeaders())
			},
		},
		{
			"ShouldRejectIssuerMismatch", errSetIssuer,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["iss"] = "https://other.example.com"

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectAudienceMismatch", errSetAudience,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["aud"] = []string{"https://other.example.com", "https://another.example.com"}

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectAnyAudienceWhenRecordHasNone", errSetAudience,
			func(t *testing.T, x *testTransmitter) string {
				x.record.Audience = nil

				return x.set().sign(t, x.claims())
			},
		},
		{
			"ShouldReportIssuerBeforeAudience", errSetIssuer,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["iss"] = "https://other.example.com"
				claims["aud"] = "https://other.example.com"
				claims["exp"] = x.now.Add(time.Hour).Unix()

				delete(claims, "jti")

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldReportAudienceBeforeOtherClaims", errSetAudience,
			func(t *testing.T, x *testTransmitter) string {
				claims := x.claims()
				claims["aud"] = "https://other.example.com"
				claims["sub"] = "user"

				delete(claims, "jti")

				return x.set().sign(t, claims)
			},
		},
		{
			"ShouldRejectJWENestingWrongTyp", errSetHeader,
			func(t *testing.T, x *testTransmitter) string {
				set := x.set()
				set.typ = "JWT"

				return testEncrypt(t, set.sign(t, x.claims()), testRecipient(testEncryptionKID), testNestedHeaders())
			},
		},
		{
			"ShouldRejectJWEWithWrongTyp", errSetHeader,
			func(t *testing.T, x *testTransmitter) string {
				headers := map[jose.HeaderKey]any{"typ": "at+jwt", "cty": "JWT"}

				return testEncrypt(t, x.set().sign(t, x.claims()), testRecipient(testEncryptionKID), headers)
			},
		},
		{
			"ShouldRejectJWEWithoutNestedContentType", errSetHeader,
			func(t *testing.T, x *testTransmitter) string {
				headers := map[jose.HeaderKey]any{"typ": "JWT"}

				return testEncrypt(t, x.set().sign(t, x.claims()), testRecipient(testEncryptionKID), headers)
			},
		},
		{
			"ShouldRejectJWEThatDoesNotNestJWS", errSetNotDecrypted,
			func(t *testing.T, x *testTransmitter) string {
				return testEncrypt(t, `{"iss":"`+x.server.URL+`"}`, testRecipient(testEncryptionKID), testNestedHeaders())
			},
		},
	}

	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			x := newTestTransmitter(t)

			event, serr, err := x.receiver.validate(t.Context(), x.record, tc.token(t, x))
			require.NoError(t, err)
			require.NotNil(t, serr)

			assert.Nil(t, event)
			// Each case is refused by one step, which the fixed error identifies.
			assert.Equal(t, tc.expected, serr)
			assert.NotSame(t, tc.expected, serr)

			// The description is a fixed string and never echoes token content.
			assert.NotEmpty(t, serr.Description)
			assert.NotContains(t, serr.Description, x.server.URL)
			assert.NotContains(t, serr.Description, testJTI)
			assert.NotContains(t, serr.Description, "other.example.com")
			assert.NotContains(t, serr.Description, "sig-0")
			assert.NotContains(t, serr.Description, "explode")
		})
	}

	t.Run("ShouldRejectTokenTheStrategyDidNotVerify", func(t *testing.T) {
		x := newTestTransmitter(t)

		x.receiver.Config.Strategy = testUnverifiedStrategy{Strategy: x.receiver.Config.Strategy}

		set := x.set()
		set.key = gen.MustES256Key()

		event, serr, err := x.receiver.validate(t.Context(), x.record, set.sign(t, x.claims()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, SetErrorAuthenticationFailed, serr.Code)
	})

	t.Run("ShouldAcceptEncryptedSET", func(t *testing.T) {
		x := newTestTransmitter(t)

		signed := x.set().sign(t, x.claims())

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, signed, testRecipient(testEncryptionKID), testNestedHeaders()))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		assert.True(t, event.Encrypted)
		assert.Equal(t, signed, event.Token)
		assert.Equal(t, testJTI, event.Claims.JTI)
	})

	t.Run("ShouldAcceptECDHESEncryptedSET", func(t *testing.T) {
		x := newTestTransmitter(t)

		signed := x.set().sign(t, x.claims())
		recipient := jose.Recipient{Algorithm: jose.ECDH_ES, Key: &testAgreementKey().PublicKey, KeyID: testAgreementKID}

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, signed, recipient, testNestedHeaders()))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		assert.True(t, event.Encrypted)
		assert.Equal(t, signed, event.Token)
	})

	t.Run("ShouldReturnInfrastructureErrorWithoutIssuerOfStrategy", func(t *testing.T) {
		x := newTestTransmitter(t)

		x.receiver.Config.Strategy = &jwt.DefaultStrategy{}

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, x.set().sign(t, x.claims()), testRecipient(testEncryptionKID), testNestedHeaders()))
		require.Error(t, err)

		assert.Nil(t, serr)
		assert.Nil(t, event)
	})

	// RFC 7516 Section 4.1.11: 'typ' is optional. RFC 8725 Section 3.11: the explicit type may repeat on the outer token.
	for name, headers := range map[string]map[jose.HeaderKey]any{
		"ShouldAcceptEncryptedSETWithoutTyp":       {"cty": "JWT"},
		"ShouldAcceptEncryptedSETWithExplicitType": {"typ": "application/secevent+jwt", "cty": "JWT"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTestTransmitter(t)

			event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, x.set().sign(t, x.claims()), testRecipient(testEncryptionKID), headers))
			require.NoError(t, err)
			require.Nil(t, serr)
			require.NotNil(t, event)
		})
	}

	t.Run("ShouldAcceptAudienceArrayWithOneMatch", func(t *testing.T) {
		x := newTestTransmitter(t)

		x.record.Audience = []string{"https://first.example.com", testAudience}

		claims := x.claims()
		claims["aud"] = []string{"https://unrelated.example.com", testAudience}

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
		require.NoError(t, err)
		require.Nil(t, serr)

		assert.Equal(t, []string{"https://unrelated.example.com", testAudience}, event.Claims.Audience)
	})

	t.Run("ShouldAcceptIssuedAtWithinClockSkew", func(t *testing.T) {
		x := newTestTransmitter(t)

		claims := x.claims()
		claims["iat"] = x.now.Add(DefaultClockSkew).Unix()

		_, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
		require.NoError(t, err)
		require.Nil(t, serr)
	})

	t.Run("ShouldKeepLargeIntegerOfPayload", func(t *testing.T) {
		x := newTestTransmitter(t)

		claims := x.claims()
		claims["events"] = map[string]any{"https://vendor.example.com/event": map[string]any{"n": json.RawMessage("9007199254740993")}}

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
		require.NoError(t, err)
		require.Nil(t, serr)

		data, err := json.Marshal(event.Payload["n"])
		require.NoError(t, err)

		assert.Equal(t, "9007199254740993", string(data))
	})

	t.Run("ShouldReturnInfrastructureErrorOnJWKSOutage", func(t *testing.T) {
		x := newTestTransmitter(t)

		x.server.status.Store(http.StatusServiceUnavailable)

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, x.claims()))
		require.Error(t, err)

		assert.Nil(t, serr)
		assert.Nil(t, event)
		assert.NotErrorIs(t, err, ErrSigningKey)
	})

	t.Run("ShouldReturnInfrastructureErrorOnRefreshOutage", func(t *testing.T) {
		x := newTestTransmitter(t)

		_, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, x.claims()))
		require.NoError(t, err)
		require.Nil(t, serr)

		x.server.status.Store(http.StatusServiceUnavailable)

		set := x.set()
		set.kid = "sig-0"

		event, serr, err := x.receiver.validate(t.Context(), x.record, set.sign(t, x.claims()))
		require.Error(t, err)

		assert.Nil(t, serr)
		assert.Nil(t, event)
	})

	t.Run("ShouldReturnInfrastructureErrorForKeyNotFetchedYet", func(t *testing.T) {
		x := newTestTransmitter(t)

		set := x.set()
		set.kid = "sig-0"

		// OpenID Connect Core Section 10.1.1: the first SET with an unfamiliar 'kid' fetches the keys again.
		_, serr, err := x.receiver.validate(t.Context(), x.record, set.sign(t, x.claims()))
		require.NoError(t, err)
		assert.Equal(t, errSetSigningKey, serr)

		// The keys can not be fetched again yet, so the SET is delivered again rather than refused.
		set.kid = "sig-9"

		event, serr, err := x.receiver.validate(t.Context(), x.record, set.sign(t, x.claims()))
		require.ErrorIs(t, err, ErrSigningKeyNotRefreshed)

		assert.Nil(t, serr)
		assert.Nil(t, event)
	})

	t.Run("ShouldReturnInfrastructureErrorWithoutStrategyOrRecord", func(t *testing.T) {
		x := newTestTransmitter(t)

		token := x.set().sign(t, x.claims())

		event, serr, err := x.receiver.validate(t.Context(), nil, token)
		require.Error(t, err)

		assert.Nil(t, serr)
		assert.Nil(t, event)

		_, serr, err = x.receiver.validate(t.Context(), &StreamRecord{StreamID: "s1", Audience: []string{testAudience}}, token)
		require.Error(t, err)
		assert.Nil(t, serr)

		x.receiver.Config.Strategy = nil

		_, serr, err = x.receiver.validate(t.Context(), x.record, token)
		require.Error(t, err)
		assert.Nil(t, serr)
	})
}

type testTokenMark struct {
	issuer, streamID, jti string
}

// testTokenStore is the TokenStorage of a Receiver under test.
type testTokenStore struct {
	StreamStorage

	now   func() time.Time
	marks map[testTokenMark]time.Time

	knownErr, markErr error
}

func (s *testTokenStore) IsSSFReceiverTokenKnown(_ context.Context, issuer, streamID, jti string) (known bool, err error) {
	if s.knownErr != nil {
		return false, s.knownErr
	}

	expires, ok := s.marks[testTokenMark{issuer, streamID, jti}]

	return ok && !expires.Before(s.now()), nil
}

func (s *testTokenStore) MarkSSFReceiverTokenReceived(_ context.Context, issuer, streamID, jti string, expiresAt time.Time) (err error) {
	if s.markErr != nil {
		return s.markErr
	}

	key := testTokenMark{issuer, streamID, jti}

	if expires, ok := s.marks[key]; ok && !expires.Before(s.now()) {
		return oauth2.ErrJTIKnown
	}

	s.marks[key] = expiresAt

	return nil
}

func (x *testTransmitter) store() *testTokenStore {
	store := &testTokenStore{now: func() time.Time { return x.now }, marks: map[testTokenMark]time.Time{}}

	x.receiver.Store = store

	return store
}

func (x *testTransmitter) event(t *testing.T, record *StreamRecord, claims map[string]any) *ReceivedEvent {
	event, serr, err := x.receiver.validate(t.Context(), record, x.set().sign(t, claims))
	require.NoError(t, err)
	require.Nil(t, serr)
	require.NotNil(t, event)

	return event
}

func TestReceiverDeduplicate(t *testing.T) {
	const day = 24 * time.Hour

	t.Run("ShouldAcknowledgeKnownJTIWithoutDispatch", func(t *testing.T) {
		x := newTestTransmitter(t)
		store := x.store()

		var dispatched int

		dispatch := func(context.Context) error {
			dispatched++

			return nil
		}

		known, err := x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), dispatch)
		require.NoError(t, err)

		assert.False(t, known)
		assert.Equal(t, 1, dispatched)
		assert.Len(t, store.marks, 1)

		// RFC 8935 Section 2: a SET received again is answered as if it had not been received before.
		known, err = x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), dispatch)
		require.NoError(t, err)

		assert.True(t, known)
		assert.Equal(t, 1, dispatched)

		claims := x.claims()
		claims["jti"] = "another"

		known, err = x.receiver.deduplicate(t.Context(), x.event(t, x.record, claims), dispatch)
		require.NoError(t, err)

		assert.False(t, known)
		assert.Equal(t, 2, dispatched)
	})

	t.Run("ShouldNotMarkWhenHandlerFails", func(t *testing.T) {
		for name, failure := range map[string]error{
			"Error":    errors.New("not persisted"),
			"SetError": &SetError{Code: SetErrorAccessDenied},
		} {
			t.Run(name, func(t *testing.T) {
				x := newTestTransmitter(t)
				store := x.store()

				var dispatched int

				known, err := x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), func(context.Context) error {
					dispatched++

					return failure
				})

				assert.False(t, known)
				assert.Same(t, failure, err)
				assert.Empty(t, store.marks)

				known, err = x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), func(context.Context) error {
					dispatched++

					return nil
				})
				require.NoError(t, err)

				assert.False(t, known)
				assert.Equal(t, 2, dispatched)
				assert.Len(t, store.marks, 1)
			})
		}
	})

	t.Run("ShouldDispatchSameJTIOnAnotherStream", func(t *testing.T) {
		x := newTestTransmitter(t)
		store := x.store()

		other := x.record.Clone()
		other.StreamID = "s2"

		var dispatched int

		for _, record := range []*StreamRecord{x.record, other} {
			known, err := x.receiver.deduplicate(t.Context(), x.event(t, record, x.claims()), func(context.Context) error {
				dispatched++

				return nil
			})
			require.NoError(t, err)

			assert.False(t, known)
		}

		assert.Equal(t, 2, dispatched)
		assert.Len(t, store.marks, 2)
	})

	t.Run("ShouldRejectTokenOlderThanMaxAge", func(t *testing.T) {
		testCases := []struct {
			name      string
			retention time.Duration
			maxAge    time.Duration
			age       time.Duration
			rejected  bool
		}{
			{"ShouldRejectOlderThanDefaultRetention", 0, 0, 30*day + time.Second, true},
			{"ShouldAcceptAtDefaultRetention", 0, 0, 30 * day, false},
			{"ShouldRejectOlderThanConfiguredRetention", time.Hour, 0, time.Hour + time.Second, true},
			{"ShouldAcceptAtConfiguredRetention", time.Hour, 0, time.Hour, false},
			{"ShouldRejectOlderThanMaxAge", 0, time.Minute, time.Minute + time.Second, true},
			{"ShouldAcceptAtMaxAge", 0, time.Minute, time.Minute, false},
			{"ShouldNotExtendMaxAgeByClockSkew", 0, time.Minute, time.Minute + DefaultClockSkew, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				x := newTestTransmitter(t)

				x.receiver.Config.TokenRetention = tc.retention
				x.receiver.Config.MaxTokenAge = tc.maxAge

				claims := x.claims()
				claims["iat"] = x.now.Add(-tc.age).Unix()

				event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
				require.NoError(t, err)

				if !tc.rejected {
					require.Nil(t, serr)
					require.NotNil(t, event)

					return
				}

				require.NotNil(t, serr)

				assert.Nil(t, event)
				assert.Equal(t, SetErrorInvalidRequest, serr.Code)
				assert.NotEmpty(t, serr.Description)
			})
		}
	})

	t.Run("ShouldAcceptOldTokenWhenAgeCheckDisabled", func(t *testing.T) {
		x := newTestTransmitter(t)

		x.receiver.Config.MaxTokenAge = -1

		claims := x.claims()
		claims["iat"] = x.now.Add(-400 * day).Unix()

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, claims))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)
	})

	t.Run("ShouldMarkUntilTokenIsRefusedByAge", func(t *testing.T) {
		testCases := []struct {
			name      string
			retention time.Duration
			maxAge    time.Duration
			issued    time.Duration
			expected  time.Duration
		}{
			{"ShouldMarkForDefaultRetention", 0, 0, -time.Hour, 30 * day},
			{"ShouldMarkForConfiguredRetention", time.Hour, 0, -time.Minute, time.Hour},
			{"ShouldMarkForRetentionWhenAgeCheckDisabled", time.Hour, -1, -400 * day, time.Hour},
			{"ShouldMarkPastRetentionForLongerMaxAge", time.Hour, 3 * time.Hour, -time.Hour, 2 * time.Hour},
			{"ShouldMarkPastRetentionForIssuedAtAhead", 0, 0, 5 * time.Second, 30*day + 5*time.Second},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				x := newTestTransmitter(t)
				store := x.store()

				x.receiver.Config.TokenRetention = tc.retention
				x.receiver.Config.MaxTokenAge = tc.maxAge

				claims := x.claims()
				claims["iat"] = x.now.Add(tc.issued).Unix()

				_, err := x.receiver.deduplicate(t.Context(), x.event(t, x.record, claims), func(context.Context) error { return nil })
				require.NoError(t, err)

				assert.Equal(t, x.now.Add(tc.expected), store.marks[testTokenMark{x.server.URL, "s1", testJTI}].UTC())
			})
		}
	})

	t.Run("ShouldAcknowledgeWhenMarkedConcurrently", func(t *testing.T) {
		x := newTestTransmitter(t)
		store := x.store()

		store.markErr = oauth2.ErrJTIKnown

		known, err := x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), func(context.Context) error { return nil })
		require.NoError(t, err)

		assert.False(t, known)
	})

	t.Run("ShouldReturnStorageError", func(t *testing.T) {
		x := newTestTransmitter(t)
		store := x.store()

		failure := errors.New("unavailable")

		var dispatched int

		dispatch := func(context.Context) error {
			dispatched++

			return nil
		}

		store.knownErr = failure

		_, err := x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), dispatch)

		assert.ErrorIs(t, err, failure)
		assert.Equal(t, 0, dispatched)

		store.knownErr, store.markErr = nil, failure

		_, err = x.receiver.deduplicate(t.Context(), x.event(t, x.record, x.claims()), dispatch)

		assert.ErrorIs(t, err, failure)
		assert.Equal(t, 1, dispatched)

		var serr *SetError

		assert.False(t, errors.As(err, &serr))
	})

	t.Run("ShouldReturnErrorWithoutStoreOrEvent", func(t *testing.T) {
		x := newTestTransmitter(t)

		event := x.event(t, x.record, x.claims())

		_, err := x.receiver.deduplicate(t.Context(), event, func(context.Context) error { return nil })
		require.Error(t, err)

		x.store()

		_, err = x.receiver.deduplicate(t.Context(), nil, func(context.Context) error { return nil })
		require.Error(t, err)
	})

	t.Run("ShouldDefaultTokenRetention", func(t *testing.T) {
		assert.Equal(t, 30*day, DefaultTokenRetention)
		assert.Equal(t, DefaultTokenRetention, (&Receiver{}).tokenRetention())
		assert.Equal(t, DefaultTokenRetention, (&Receiver{Config: Config{TokenRetention: -1}}).tokenRetention())
		assert.Equal(t, time.Hour, (&Receiver{Config: Config{TokenRetention: time.Hour}}).tokenRetention())
	})
}
