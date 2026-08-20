/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"testing"

	"authelia.com/provider/oauth2/token/jose/json"
	"authelia.com/provider/oauth2/token/jose/testutils/assert"
	"authelia.com/provider/oauth2/token/jose/testutils/require"
)

func TestEd25519(t *testing.T) {
	_, err := newEd25519Signer("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(edEncrypterVerifier)
	enc.publicKey = ed25519PublicKey
	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	dec := new(edDecrypterSigner)
	dec.privateKey = ed25519PrivateKey
	_, err = dec.signPayload([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	sig, err := dec.signPayload([]byte("This is a test"), "EdDSA")
	if err != nil {
		t.Error("should not error trying to sign payload")
	}
	if sig.Signature == nil {
		t.Error("Check the signature")
	}
	err = enc.verifyPayload([]byte("This is a test"), sig.Signature, "EdDSA")
	if err != nil {
		t.Error("should not error trying to verify payload")
	}

	err = enc.verifyPayload([]byte("This is test number 2"), sig.Signature, "EdDSA")
	if err == nil {
		t.Error("should not error trying to verify payload")
	}
}

func TestInvalidAlgorithmsRSA(t *testing.T) {
	_, err := newRSARecipient("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = newRSASigner("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &rsaTestKey.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	_, err = dec.decrypt(make([]byte, 256), "XYZ", randomKeyGenerator{size: 16})
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = dec.signPayload([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}
}

type failingKeyGenerator struct{}

func (ctx failingKeyGenerator) keySize() int {
	return 0
}

func (ctx failingKeyGenerator) genKey() ([]byte, rawHeader, error) {
	return nil, rawHeader{}, errors.New("failed to generate key")
}

func TestPKCSKeyGeneratorFailure(t *testing.T) {
	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	generator := failingKeyGenerator{}
	_, err := dec.decrypt(make([]byte, 256), RSA1_5, generator)
	if err != ErrCryptoFailure {
		t.Error("should return error on invalid algorithm")
	}
}

func TestInvalidAlgorithmsEC(t *testing.T) {
	_, err := newECDHRecipient("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	_, err = newECDSASigner("XYZ", nil)
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}

	enc := new(ecEncrypterVerifier)
	enc.publicKey = &ecTestKey256.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Error("should return error on invalid algorithm")
	}
}

func TestInvalidECKeyGen(t *testing.T) {
	gen := ecKeyGenerator{
		size:      16,
		algID:     "A128GCM",
		publicKey: &ecTestKey256.PublicKey,
	}

	if gen.keySize() != 16 {
		t.Error("ec key generator reported incorrect key size")
	}

	_, _, err := gen.genKey()
	if err != nil {
		t.Error("ec key generator failed to generate key", err)
	}
}

func TestInvalidECDecrypt(t *testing.T) {
	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	generator := randomKeyGenerator{size: 16}

	recipient := recipientInfo{
		// decryptKey will error out before the contents here matter
		encryptedKey: []byte("not used"),
	}
	// Missing epk header
	headers := rawHeader{}

	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}

	want := "go-jose/go-jose: missing epk header"
	_, err := dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with missing epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with missing epk header: got %q, want %q", err, want)
	}

	// Invalid epk header
	invalid := json.RawMessage("invalid")
	headers["epk"] = &invalid

	want = "go-jose/go-jose: invalid epk header"
	_, err = dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with invalid epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with invalid epk header: got %q, want %q", err, want)
	}
}

func TestDecryptWithIncorrectSize(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	payload := make([]byte, 254)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	if err == nil {
		t.Error("Invalid payload size should return error")
	}

	payload = make([]byte, 257)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	if err == nil {
		t.Error("Invalid payload size should return error")
	}
}

func TestPKCSDecryptNeverFails(t *testing.T) {
	// We don't want RSA-PKCS1 v1.5 decryption to ever fail, in order to prevent
	// side-channel timing attacks (Bleichenbacher attack in particular).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	for i := 1; i < 50; i++ {
		payload := make([]byte, 256)
		_, err := io.ReadFull(rand.Reader, payload)
		if err != nil {
			t.Error("Unable to get random data:", err)
			return
		}
		_, err = dec.decrypt(payload, RSA1_5, keygen)
		if err != nil {
			t.Error("PKCS1v1.5 decrypt should never fail:", err)
			return
		}
	}
}

func BenchmarkPKCSDecryptWithValidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(32)

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		keygen := randomKeyGenerator{
			size: aes.keySize(),
		}

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkPKCSDecryptWithInvalidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		// Do some simple scrambling
		ciphertext[128] ^= 0xFF

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func TestInvalidEllipticCurve(t *testing.T) {
	signer256 := ecDecrypterSigner{privateKey: ecTestKey256}
	signer384 := ecDecrypterSigner{privateKey: ecTestKey384}
	signer521 := ecDecrypterSigner{privateKey: ecTestKey521}

	_, err := signer256.signPayload([]byte{}, ES384)
	if err == nil {
		t.Error("should not generate ES384 signature with P-256 key")
	}
	_, err = signer256.signPayload([]byte{}, ES512)
	if err == nil {
		t.Error("should not generate ES512 signature with P-256 key")
	}
	_, err = signer384.signPayload([]byte{}, ES256)
	if err == nil {
		t.Error("should not generate ES256 signature with P-384 key")
	}
	_, err = signer384.signPayload([]byte{}, ES512)
	if err == nil {
		t.Error("should not generate ES512 signature with P-384 key")
	}
	_, err = signer521.signPayload([]byte{}, ES256)
	if err == nil {
		t.Error("should not generate ES256 signature with P-521 key")
	}
	_, err = signer521.signPayload([]byte{}, ES384)
	if err == nil {
		t.Error("should not generate ES384 signature with P-521 key")
	}
}

func TestInvalidECPublicKey(t *testing.T) {
	// Invalid key
	invalid := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     fromBase64Int("MTEx"),
			Y:     fromBase64Int("MTEx"),
		},
		D: fromBase64Int("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
	}

	recipient := recipientInfo{
		// encryptedKey must be non-empty to pass initial checks, but the actual
		// bytes don't matter because we'll error out before using them.
		encryptedKey: []byte("not used"),
	}

	headers := rawHeader{}

	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}

	if err := headers.set(headerEPK, &JSONWebKey{Key: &invalid.PublicKey}); err != nil {
		t.Fatal(err)
	}

	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	_, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16})
	if err == nil {
		t.Fatal("decrypter accepted JWS with invalid ECDH public key")
	}

	want := "go-jose/go-jose: invalid epk header"
	if err.Error() != want {
		t.Errorf("decryptKey with invalid ECDH public key: got %q, want %q", err, want)
	}
}

func TestInvalidAlgorithmEC(t *testing.T) {
	err := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}.verifyPayload([]byte{}, []byte{}, "XYZ")
	if err != ErrUnsupportedAlgorithm {
		t.Fatal("should not accept invalid/unsupported algorithm")
	}
}

func TestECDHDecryptKeyRejectsEPKOnAnotherCurve(t *testing.T) {
	testCases := []struct {
		name string
		epk  *ecdsa.PublicKey
		err  string
	}{
		{"ShouldAcceptMatchingCurve", &ecTestKey256.PublicKey, ""},
		{"ShouldRejectLargerCurve", &ecTestKey384.PublicKey, "go-jose/go-jose: invalid public key in epk header"},
		{"ShouldRejectSmallerCurve", &ecTestKey521.PublicKey, "go-jose/go-jose: invalid public key in epk header"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := rawHeader{}

			require.NoError(t, headers.set(headerEPK, &JSONWebKey{Key: tc.epk}))
			require.NoError(t, headers.set(headerAlgorithm, ECDH_ES))

			ctx := ecDecrypterSigner{privateKey: ecTestKey256}

			_, err := ctx.decryptKey(headers, &recipientInfo{}, randomKeyGenerator{size: 16})

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			if err == nil {
				t.Fatal("accepted an epk header on another curve")
			}

			assert.Equal(t, err.Error(), tc.err)
		})
	}
}

// RFC 7518 Section 3.4 pairs each ECDSA algorithm with exactly one curve.
func TestECDSAVerifyRejectsWrongCurveForAlgorithm(t *testing.T) {
	testCases := []struct {
		alg       SignatureAlgorithm
		curve     elliptic.Curve
		hash      crypto.Hash
		sigOctets int
	}{
		{ES384, elliptic.P256(), crypto.SHA384, 48},
		{ES512, elliptic.P256(), crypto.SHA512, 66},
		{ES512, elliptic.P384(), crypto.SHA512, 66},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_with_%s", tc.alg, tc.curve.Params().Name), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte("payload")
			hasher := tc.hash.New()
			hasher.Write(payload)

			r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
			if err != nil {
				t.Fatal(err)
			}

			signature := make([]byte, 2*tc.sigOctets)
			r.FillBytes(signature[:tc.sigOctets])
			s.FillBytes(signature[tc.sigOctets:])

			verifier := &ecEncrypterVerifier{publicKey: &key.PublicKey}
			if err = verifier.verifyPayload(payload, signature, tc.alg); err == nil {
				t.Errorf("verifyPayload accepted a %s signature under %s, want an error",
					tc.curve.Params().Name, tc.alg)
			}
		})
	}
}

// The matching curve must still verify, and each algorithm must still reject a
// signature made over the wrong digest on the right curve.
func TestECDSAVerifyAcceptsMatchingCurve(t *testing.T) {
	testCases := []struct {
		alg   SignatureAlgorithm
		curve elliptic.Curve
	}{
		{ES256, elliptic.P256()},
		{ES384, elliptic.P384()},
		{ES512, elliptic.P521()},
	}

	for _, tc := range testCases {
		t.Run(string(tc.alg), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			signer := &ecDecrypterSigner{privateKey: key}
			payload := []byte("payload")

			sig, err := signer.signPayload(payload, tc.alg)
			if err != nil {
				t.Fatalf("signPayload: %v", err)
			}

			verifier := &ecEncrypterVerifier{publicKey: &key.PublicKey}
			if err = verifier.verifyPayload(payload, sig.Signature, tc.alg); err != nil {
				t.Errorf("verifyPayload rejected a matching %s signature: %v", tc.alg, err)
			}

			if err = verifier.verifyPayload([]byte("other"), sig.Signature, tc.alg); err == nil {
				t.Errorf("verifyPayload accepted a signature over a different payload")
			}
		})
	}
}

func TestECDSAVerifyRejectsNilKey(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("verifyPayload panicked on a nil public key: %v", r)
		}
	}()

	verifier := &ecEncrypterVerifier{publicKey: nil}
	if err := verifier.verifyPayload([]byte("payload"), make([]byte, 64), ES256); err == nil {
		t.Error("verifyPayload accepted a nil public key, want an error")
	}
}

// RFC 7518 Sections 3.3, 3.5, 4.2 and 4.3 each require a modulus of at least
// 2048 bits.
func TestRSARejectsUndersizedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	signer := &rsaDecrypterSigner{privateKey: small}
	verifier := &rsaEncrypterVerifier{publicKey: &small.PublicKey}

	for _, alg := range []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512} {
		if _, err = signer.signPayload([]byte("payload"), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("signPayload(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}

		if err = verifier.verifyPayload([]byte("payload"), make([]byte, 128), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("verifyPayload(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}
	}

	for _, alg := range []KeyAlgorithm{RSA1_5, RSA_OAEP, RSA_OAEP_256} {
		if _, err = verifier.encrypt(make([]byte, 32), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("encrypt(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}

		if _, err = signer.decrypt(make([]byte, 128), alg, randomKeyGenerator{size: 32}); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("decrypt(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}
	}
}

func TestRSAAcceptsMinimumKeySize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minRSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}

	signer := &rsaDecrypterSigner{privateKey: key}
	verifier := &rsaEncrypterVerifier{publicKey: &key.PublicKey}

	for _, alg := range []SignatureAlgorithm{RS256, PS512} {
		sig, err := signer.signPayload([]byte("payload"), alg)
		if err != nil {
			t.Fatalf("signPayload(%s) with a %d bit key: %v", alg, minRSAKeyBits, err)
		}

		if err = verifier.verifyPayload([]byte("payload"), sig.Signature, alg); err != nil {
			t.Errorf("verifyPayload(%s) rejected a conforming key: %v", alg, err)
		}
	}
}

func TestRSARejectsNilKeys(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked on a nil key: %v", r)
		}
	}()

	verifier := &rsaEncrypterVerifier{publicKey: nil}
	if err := verifier.verifyPayload([]byte("payload"), make([]byte, 256), RS256); err == nil {
		t.Error("verifyPayload accepted a nil public key, want an error")
	}

	signer := &rsaDecrypterSigner{privateKey: nil}
	if _, err := signer.signPayload([]byte("payload"), RS256); err == nil {
		t.Error("signPayload accepted a nil private key, want an error")
	}
}

// A low-order Ed25519 public key admits a single signature that verifies for
// every message: verification reduces to [S]B = R + [k]A, and for the identity
// point [k]A is the identity whatever the message hashes to, so R = identity
// with S = 0 satisfies it universally. The fork screens for these keys when
// parsing a JWK, but Verify also accepts a raw ed25519.PublicKey, and that path
// reached crypto/ed25519 unscreened.
func TestEd25519VerifyRejectsLowOrderKey(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	publicKey[0] = 0x01 // identity point

	signature := make([]byte, ed25519.SignatureSize)
	signature[0] = 0x01 // R = identity, S = 0

	// Precondition: crypto/ed25519 itself accepts this, for any message.
	if !ed25519.Verify(publicKey, []byte("first message"), signature) {
		t.Fatal("precondition failed: crypto/ed25519 rejected the forgery")
	}

	verifier := &edEncrypterVerifier{publicKey: publicKey}

	for _, message := range []string{"first message", "a completely different message"} {
		if err := verifier.verifyPayload([]byte(message), signature, EdDSA); err == nil {
			t.Errorf("verifyPayload accepted a low-order key for %q, want an error", message)
		}
	}
}

// Wrong-length keys panicked inside crypto/ed25519 instead of erroring.
func TestEd25519RejectsMalformedKeys(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked on a malformed key: %v", r)
		}
	}()

	for _, publicKey := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33)} {
		verifier := &edEncrypterVerifier{publicKey: publicKey}
		if err := verifier.verifyPayload([]byte("payload"), make([]byte, ed25519.SignatureSize), EdDSA); err == nil {
			t.Errorf("verifyPayload accepted a %d byte public key, want an error", len(publicKey))
		}
	}

	for _, privateKey := range []ed25519.PrivateKey{nil, make([]byte, 63), make([]byte, 65)} {
		signer := &edDecrypterSigner{privateKey: privateKey}
		if _, err := signer.signPayload([]byte("payload"), EdDSA); err == nil {
			t.Errorf("signPayload accepted a %d byte private key, want an error", len(privateKey))
		}
	}
}

// A genuine key must still round-trip, and a signature over another payload
// must still be rejected.
func TestEd25519AcceptsValidKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := &edDecrypterSigner{privateKey: private}
	verifier := &edEncrypterVerifier{publicKey: public}

	sig, err := signer.signPayload([]byte("payload"), EdDSA)
	if err != nil {
		t.Fatalf("signPayload: %v", err)
	}

	if err = verifier.verifyPayload([]byte("payload"), sig.Signature, EdDSA); err != nil {
		t.Errorf("verifyPayload rejected a valid signature: %v", err)
	}

	if err = verifier.verifyPayload([]byte("other"), sig.Signature, EdDSA); err == nil {
		t.Error("verifyPayload accepted a signature over a different payload")
	}
}

// RFC 9864 Section 2.2 registers "Ed25519" as the fully-specified identifier for
// the parameter set that RFC 8037's polymorphic "EdDSA" leaves unstated, and
// Section 4.1.2 deprecates "EdDSA" in the registry. Both name the same
// operation, so a signature made under one identifier verifies under the other.
func TestEd25519FullySpecifiedAlgorithm(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := &edDecrypterSigner{privateKey: private}
	verifier := &edEncrypterVerifier{publicKey: public}

	algorithms := []SignatureAlgorithm{EdDSA, Ed25519}

	for _, signAlg := range algorithms {
		sig, err := signer.signPayload([]byte("payload"), signAlg)
		if err != nil {
			t.Fatalf("signPayload(%s): %v", signAlg, err)
		}

		for _, verifyAlg := range algorithms {
			if err = verifier.verifyPayload([]byte("payload"), sig.Signature, verifyAlg); err != nil {
				t.Errorf("signed under %s, verifying under %s: %v", signAlg, verifyAlg, err)
			}
		}
	}

	// An unrelated algorithm must still be refused.
	if err = verifier.verifyPayload([]byte("payload"), make([]byte, 64), ES256); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("verifyPayload(ES256) = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

func TestEd25519AlgorithmReachesTheHeader(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, alg := range []SignatureAlgorithm{EdDSA, Ed25519} {
		signer, err := NewSigner(SigningKey{Algorithm: alg, Key: private}, nil)
		if err != nil {
			t.Fatalf("NewSigner(%s): %v", alg, err)
		}

		obj, err := signer.Sign([]byte("payload"))
		if err != nil {
			t.Fatalf("Sign(%s): %v", alg, err)
		}

		serialized, err := obj.CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize(%s): %v", alg, err)
		}

		parsed, err := ParseSignedCompact(serialized, []SignatureAlgorithm{alg})
		if err != nil {
			t.Fatalf("ParseSignedCompact(%s): %v", alg, err)
		}

		if got := parsed.Signatures[0].Header.Algorithm; got != string(alg) {
			t.Errorf("header alg = %q, want %q", got, alg)
		}

		other := EdDSA
		if alg == EdDSA {
			other = Ed25519
		}

		if _, err = ParseSignedCompact(serialized, []SignatureAlgorithm{other}); err == nil {
			t.Errorf("a %s token was accepted by a parse restricted to %s", alg, other)
		}
	}
}
