// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testProfileKID      = "rsa-2048"
	testProfileSmallKID = "rsa-1024"
)

var (
	testProfileKey = sync.OnceValue(gen.MustRSAKey)

	testProfileSmallKey = sync.OnceValue(func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}

		return key
	})
)

func testProfileMetadata() map[string]any {
	return map[string]any{
		"delivery_methods_supported": []string{oauth2.SSFDeliveryMethodPush, oauth2.SSFDeliveryMethodPoll},
		"authorization_schemes":      []map[string]any{{"spec_urn": oauth2.SSFAuthorizationSchemeOAuth2}},
	}
}

// newTestProfileTransmitter is a Transmitter which meets the CAEP Interoperability Profile, with a 2048 bit and a 1024
// bit RSA key beside the ES256 key, and a Receiver which enforces the profile when enforce is true.
func newTestProfileTransmitter(t *testing.T, enforce bool) *testTransmitter {
	x := newTestTransmitter(t)

	metadata := testProfileMetadata()

	x.server.extra.Store(&metadata)
	x.server.setKeys(
		jose.JSONWebKey{Key: &x.key.PublicKey, KeyID: testSignatureKID, Use: "sig", Algorithm: string(jose.ES256)},
		jose.JSONWebKey{Key: &testProfileKey().PublicKey, KeyID: testProfileKID, Use: "sig", Algorithm: string(jose.RS256)},
		jose.JSONWebKey{Key: &testProfileSmallKey().PublicKey, KeyID: testProfileSmallKID, Use: "sig", Algorithm: string(jose.RS256)},
	)

	x.receiver.Config.EnforceCAEPInteroperabilityProfile = enforce

	return x
}

func (x *testTransmitter) profileSET() testSET {
	return testSET{typ: testTypeSET, kid: testProfileKID, alg: jose.RS256, key: testProfileKey()}
}

// testSignSmall returns a SET with an RS256 signature of the 1024 bit key, which the JOSE library refuses to produce.
func testSignSmall(t *testing.T, claims map[string]any) string {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": testTypeSET, "kid": testProfileSmallKID})
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))

	signature, err := rsa.SignPKCS1v15(rand.Reader, testProfileSmallKey(), crypto.SHA256, digest[:])
	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestReceiverInteroperabilityProfile(t *testing.T) {
	t.Run("ShouldAcceptRS256UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.profileSET().sign(t, x.claims()))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		assert.Equal(t, testJTI, event.Claims.JTI)
	})

	t.Run("ShouldRejectES256UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, x.claims()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, errSetSigningAlgorithm, serr)
		assert.Equal(t, SetErrorInvalidKey, serr.Code)
	})

	t.Run("ShouldRejectES256UnderProfileWhenConfigured", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		x.receiver.Config.SigningAlgs = []string{"ES256", "RS256"}

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, x.claims()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, errSetSigningAlgorithm, serr)
	})

	t.Run("ShouldRejectOtherRSAAlgorithmsUnderProfile", func(t *testing.T) {
		for _, alg := range []jose.SignatureAlgorithm{jose.RS384, jose.RS512, jose.PS256} {
			x := newTestProfileTransmitter(t, true)

			set := x.profileSET()
			set.alg = alg

			event, serr, err := x.receiver.validate(t.Context(), x.record, set.sign(t, x.claims()))
			require.NoError(t, err)
			require.NotNil(t, serr)

			assert.Nil(t, event)
			assert.Equal(t, errSetSigningAlgorithm, serr)
		}
	})

	t.Run("ShouldRejectRSA1024UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		event, serr, err := x.receiver.validate(t.Context(), x.record, testSignSmall(t, x.claims()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, errSetSigningKey, serr)
		assert.Equal(t, SetErrorInvalidKey, serr.Code)
	})

	t.Run("ShouldAcceptEncryptedRS256UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		signed := x.profileSET().sign(t, x.claims())

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, signed, testRecipient(testEncryptionKID), testNestedHeaders()))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		assert.True(t, event.Encrypted)
		assert.Equal(t, signed, event.Token)
	})

	t.Run("ShouldRejectEncryptedES256UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		signed := x.set().sign(t, x.claims())

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, signed, testRecipient(testEncryptionKID), testNestedHeaders()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, errSetSigningAlgorithm, serr)
	})

	t.Run("ShouldRejectEncryptedRSA1024UnderProfile", func(t *testing.T) {
		x := newTestProfileTransmitter(t, true)

		event, serr, err := x.receiver.validate(t.Context(), x.record, testEncrypt(t, testSignSmall(t, x.claims()), testRecipient(testEncryptionKID), testNestedHeaders()))
		require.NoError(t, err)
		require.NotNil(t, serr)

		assert.Nil(t, event)
		assert.Equal(t, errSetSigningKey, serr)
	})

	t.Run("ShouldRejectMetadataWithoutOAuthScheme", func(t *testing.T) {
		schemes := map[string]any{
			"Absent": nil,
			"Empty":  []map[string]any{},
			"Other":  []map[string]any{{"spec_urn": "urn:ietf:rfc:7523"}},
		}

		for name, value := range schemes {
			t.Run(name, func(t *testing.T) {
				x := newTestProfileTransmitter(t, true)

				metadata := testProfileMetadata()
				metadata["authorization_schemes"] = value

				x.server.extra.Store(&metadata)

				configuration, err := x.receiver.Discover(t.Context(), x.server.URL)
				require.Error(t, err)

				assert.Nil(t, configuration)
				assert.ErrorContains(t, err, "'authorization_schemes' does not meet the CAEP Interoperability Profile")
				assert.Empty(t, x.receiver.metadata.entries)

				// A SET is not validated against keys of metadata that is refused, and it is not a fault of the SET.
				event, serr, err := x.receiver.validate(t.Context(), x.record, x.profileSET().sign(t, x.claims()))
				require.Error(t, err)

				assert.Nil(t, serr)
				assert.Nil(t, event)
			})
		}
	})

	t.Run("ShouldAcceptEmailAndIssSubSubjects", func(t *testing.T) {
		subjects := map[string]map[string]any{
			jwt.SubjectIdentifierFormatEmail:         {"format": "email", "email": "user@example.com"},
			jwt.SubjectIdentifierFormatIssuerSubject: {"format": "iss_sub", "iss": "https://idp.example.com", "sub": "user-1"},
		}

		for format, subject := range subjects {
			t.Run(format, func(t *testing.T) {
				x := newTestProfileTransmitter(t, true)

				claims := x.claims()
				claims["sub_id"] = subject

				event, serr, err := x.receiver.validate(t.Context(), x.record, x.profileSET().sign(t, claims))
				require.NoError(t, err)
				require.Nil(t, serr)
				require.NotNil(t, event)

				assert.Equal(t, format, event.Claims.SubjectIdentifier.Format)
			})
		}
	})

	t.Run("ShouldNotApplyProfileByDefault", func(t *testing.T) {
		x := newTestProfileTransmitter(t, false)

		assert.False(t, (&Config{}).EnforceCAEPInteroperabilityProfile)

		event, serr, err := x.receiver.validate(t.Context(), x.record, x.set().sign(t, x.claims()))
		require.NoError(t, err)
		require.Nil(t, serr)
		require.NotNil(t, event)

		// The JOSE library does not verify with an RSA key of less than 2048 bits, and the key itself is not refused.
		event, serr, err = x.receiver.validate(t.Context(), x.record, testSignSmall(t, x.claims()))
		require.NoError(t, err)

		assert.Nil(t, event)
		assert.Equal(t, errSetSignature, serr)
	})
}
