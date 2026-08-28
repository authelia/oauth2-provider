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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"authelia.com/provider/oauth2/token/jose/json"
)

// NonceSource represents a source of random nonces to go into JWS objects
type NonceSource interface {
	Nonce() (string, error)
}

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer interface {
	Sign(payload []byte) (*JSONWebSignature, error)
	Options() SignerOptions
}

// SigningKey represents an algorithm/key used to sign a message.
//
// Key must have one of these types:
//   - ed25519.PrivateKey
//   - *mldsa.PrivateKey (requires Go 1.27 or later)
//   - *ecdsa.PrivateKey
//   - *rsa.PrivateKey
//   - *JSONWebKey
//   - JSONWebKey
//   - []byte (an HMAC key)
//   - Any type that satisfies the OpaqueSigner interface
//
// If the key is an HMAC key, it must have at least as many bytes as the relevant hash output:
//   - HS256: 32 bytes
//   - HS384: 48 bytes
//   - HS512: 64 bytes
type SigningKey struct {
	Algorithm SignatureAlgorithm
	Key       any
}

// SignerOptions represents options that can be set when creating signers.
type SignerOptions struct {
	NonceSource NonceSource
	EmbedJWK    bool

	// Optional map of additional keys to be inserted into the protected header
	// of a JWS object. Some specifications which make use of JWS like to insert
	// additional values here.
	//
	// Values will be serialized by [json.Marshal] and must be valid inputs to
	// that function.
	//
	// These are written over the protected header the signer assembles, so "alg"
	// is rejected by [NewSigner] and [NewMultiSigner]: it follows from the
	// signing key, and a value supplied here would be the header a recipient
	// trusts while the signature was made with something else. "kid", "typ",
	// "cty" and any extension parameter are the caller's to set. "b64" is too,
	// but only alongside a "crit" which lists it, as RFC 7797 Section 6
	// requires; [SignerOptions.WithBase64] sets the pair together.
	//
	// [json.Marshal]: https://pkg.go.dev/encoding/json#Marshal
	ExtraHeaders map[HeaderKey]any
}

// WithHeader adds an arbitrary value to the ExtraHeaders map, initializing it
// if necessary, and returns the updated SignerOptions.
//
// The v argument will be serialized by [json.Marshal] and must be a valid
// input to that function.
//
// [json.Marshal]: https://pkg.go.dev/encoding/json#Marshal
func (so *SignerOptions) WithHeader(k HeaderKey, v any) *SignerOptions {
	if so.ExtraHeaders == nil {
		so.ExtraHeaders = map[HeaderKey]any{}
	}
	so.ExtraHeaders[k] = v
	return so
}

// WithContentType adds a content type ("cty") header and returns the updated
// SignerOptions.
func (so *SignerOptions) WithContentType(contentType ContentType) *SignerOptions {
	return so.WithHeader(HeaderContentType, contentType)
}

// WithType adds a type ("typ") header and returns the updated SignerOptions.
func (so *SignerOptions) WithType(typ ContentType) *SignerOptions {
	return so.WithHeader(HeaderType, typ)
}

// WithCritical adds the given names to the critical ("crit") header and returns
// the updated SignerOptions.
func (so *SignerOptions) WithCritical(names ...string) *SignerOptions {
	if so.ExtraHeaders[headerCritical] == nil {
		so.WithHeader(headerCritical, make([]string, 0, len(names)))
	}
	crit := so.ExtraHeaders[headerCritical].([]string)
	so.ExtraHeaders[headerCritical] = append(crit, names...)
	return so
}

// WithBase64 adds a base64url-encode payload ("b64") header and returns the updated
// SignerOptions. When the "b64" value is "false", the payload is not base64 encoded.
func (so *SignerOptions) WithBase64(b64 bool) *SignerOptions {
	if !b64 {
		so.WithHeader(headerB64, b64)
		so.WithCritical(headerB64)
	}
	return so
}

// checkExtraB64Critical applies RFC 7797 Section 6 to a signer's extra headers. Unlike "alg", "b64" is the
// caller's to set -- SignerOptions.WithBase64 routes through the same map -- but only alongside a "crit" which
// lists it. WithBase64 sets the pair together; a caller reaching for WithHeader on its own would otherwise emit
// a JWS this package refuses to parse.
func checkExtraB64Critical(extra map[HeaderKey]any) error {
	if _, ok := extra[headerB64]; !ok {
		return nil
	}

	var names []string

	// WithCritical builds a []string, while a caller which round-trips its headers through JSON has an []any.
	switch crit := extra[headerCritical].(type) {
	case []string:
		names = crit
	case []any:
		for _, name := range crit {
			if s, ok := name.(string); ok {
				names = append(names, s)
			}
		}
	}

	for _, name := range names {
		if name == headerB64 {
			return nil
		}
	}

	return ErrB64NotCritical
}

type payloadSigner interface {
	signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error)
}

type payloadVerifier interface {
	verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type genericSigner struct {
	recipients   []recipientSigInfo
	nonceSource  NonceSource
	embedJWK     bool
	extraHeaders map[HeaderKey]any
}

type recipientSigInfo struct {
	sigAlg SignatureAlgorithm
	// publicKey returns a synthetic JSONWebKey for the signer.
	// For opaque signers, it calls OpaqueSigner.Public().
	publicKey func() *JSONWebKey
	signer    payloadSigner
}

// getPublicKey gets the public key, with a nil check on the func.
func (r recipientSigInfo) getPublicKey() *JSONWebKey {
	if r.publicKey == nil {
		return nil
	}
	return r.publicKey()
}

func staticPublicKey(jwk *JSONWebKey) func() *JSONWebKey {
	return func() *JSONWebKey {
		return jwk
	}
}

// NewSigner creates an appropriate signer based on the key type
func NewSigner(sig SigningKey, opts *SignerOptions) (Signer, error) {
	return NewMultiSigner([]SigningKey{sig}, opts)
}

// NewMultiSigner creates a signer for multiple recipients
func NewMultiSigner(sigs []SigningKey, opts *SignerOptions) (Signer, error) {
	signer := &genericSigner{recipients: []recipientSigInfo{}}

	if opts != nil {
		signer.nonceSource = opts.NonceSource
		signer.embedJWK = opts.EmbedJWK
		signer.extraHeaders = opts.ExtraHeaders

		// RFC 7515 Section 4.1.1 makes "alg" the parameter a recipient trusts to pick its verification, and it
		// follows from the signing key rather than from the caller.
		if err := checkExtraHeaders(signer.extraHeaders, headerAlgorithm); err != nil {
			return nil, err
		}

		if err := checkExtraB64Critical(signer.extraHeaders); err != nil {
			return nil, err
		}
	}

	for _, sig := range sigs {
		err := signer.addRecipient(sig.Algorithm, sig.Key)
		if err != nil {
			return nil, err
		}
	}

	return signer, nil
}

// newVerifier creates a verifier based on the key type
func newVerifier(verificationKey any) (payloadVerifier, error) {
	switch verificationKey := verificationKey.(type) {
	case ed25519.PublicKey:
		return &edEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case *rsa.PublicKey:
		return &rsaEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case *ecdsa.PublicKey:
		return &ecEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case []byte:
		return &symmetricMac{
			key: verificationKey,
		}, nil
	case JSONWebKey:
		return newVerifier(verificationKey.Key)
	case *JSONWebKey:
		return newVerifier(verificationKey.Key)
	case OpaqueVerifier:
		return &opaqueVerifier{verifier: verificationKey}, nil
	default:
		if verifier, ok, err := mldsaVerifier(verificationKey); ok {
			return verifier, err
		}
		return nil, ErrUnsupportedKeyType
	}
}

func (ctx *genericSigner) addRecipient(alg SignatureAlgorithm, signingKey any) error {
	recipient, err := makeJWSRecipient(alg, signingKey)
	if err != nil {
		return err
	}

	ctx.recipients = append(ctx.recipients, recipient)
	return nil
}

func makeJWSRecipient(alg SignatureAlgorithm, signingKey any) (recipientSigInfo, error) {
	switch signingKey := signingKey.(type) {
	case ed25519.PrivateKey:
		return newEd25519Signer(alg, signingKey)
	case *rsa.PrivateKey:
		return newRSASigner(alg, signingKey)
	case *ecdsa.PrivateKey:
		return newECDSASigner(alg, signingKey)
	case []byte:
		return newSymmetricSigner(alg, signingKey)
	case JSONWebKey:
		return newJWKSigner(alg, signingKey)
	case *JSONWebKey:
		return newJWKSigner(alg, *signingKey)
	case OpaqueSigner:
		return newOpaqueSigner(alg, signingKey)
	default:
		if recipient, ok, err := mldsaSigner(alg, signingKey); ok {
			return recipient, err
		}
		return recipientSigInfo{}, ErrUnsupportedKeyType
	}
}

func newJWKSigner(alg SignatureAlgorithm, signingKey JSONWebKey) (recipientSigInfo, error) {
	recipient, err := makeJWSRecipient(alg, signingKey.Key)
	if err != nil {
		return recipientSigInfo{}, err
	}
	if recipientPubKey := recipient.getPublicKey(); recipientPubKey != nil {
		// This should be impossible, but let's check anyway.
		if !recipientPubKey.IsPublic() {
			return recipientSigInfo{}, ErrNotPublic
		}

		// recipient.publicKey is a JWK synthesized for embedding when recipientSigInfo
		// was created for the inner key (such as a RSA or ECDSA public key). It contains
		// the pub key for embedding, but doesn't have extra params like key id.
		publicKey := signingKey
		publicKey.Key = recipientPubKey.Key
		recipient.publicKey = staticPublicKey(&publicKey)
	}
	return recipient, nil
}

func (ctx *genericSigner) Sign(payload []byte) (*JSONWebSignature, error) {
	obj := &JSONWebSignature{}
	obj.payload = payload
	obj.Signatures = make([]Signature, len(ctx.recipients))

	for i, recipient := range ctx.recipients {
		protected := map[HeaderKey]any{
			headerAlgorithm: string(recipient.sigAlg),
		}

		if recipientPubKey := recipient.getPublicKey(); recipientPubKey != nil {
			// We want to embed the JWK or set the kid header, but not both. Having a protected
			// header that contains an embedded JWK while also simultaneously containing the kid
			// header is confusing, and at least in ACME the two are considered to be mutually
			// exclusive. The fact that both can exist at the same time is a somewhat unfortunate
			// result of the JOSE spec. We've decided that this library will only include one or
			// the other to avoid this confusion.
			//
			// See https://github.com/square/go-jose/issues/157 for more context.
			if ctx.embedJWK {
				// MarshalJSON can fail for a semantically inconsistent key (an AKP
				// key whose Algorithm contradicts its parameter set). Surface that
				// as an error rather than letting mustSerializeJSON panic below.
				if _, err := recipientPubKey.MarshalJSON(); err != nil {
					return nil, err
				}
				protected[headerJWK] = recipientPubKey
			} else {
				keyID := recipientPubKey.KeyID
				if keyID != "" {
					protected[headerKeyID] = keyID
				}
			}
		}

		if ctx.nonceSource != nil {
			nonce, err := ctx.nonceSource.Nonce()
			if err != nil {
				return nil, fmt.Errorf("go-jose/go-jose: Error generating nonce: %v", err)
			}
			protected[headerNonce] = nonce
		}

		for k, v := range ctx.extraHeaders {
			protected[k] = v
		}

		serializedProtected := mustSerializeJSON(protected)
		needsBase64 := true

		if b64, ok := protected[headerB64]; ok {
			if needsBase64, ok = b64.(bool); !ok {
				return nil, errors.New("go-jose/go-jose: Invalid b64 header parameter")
			}
		}

		var input bytes.Buffer

		input.WriteString(base64.RawURLEncoding.EncodeToString(serializedProtected))
		input.WriteByte('.')

		if needsBase64 {
			input.WriteString(base64.RawURLEncoding.EncodeToString(payload))
		} else {
			input.Write(payload)
		}

		signatureInfo, err := recipient.signer.signPayload(input.Bytes(), recipient.sigAlg)
		if err != nil {
			return nil, err
		}

		signatureInfo.protected = &rawHeader{}
		for k, v := range protected {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("go-jose/go-jose: Error marshalling item %#v: %v", k, err)
			}
			(*signatureInfo.protected)[k] = makeRawMessage(b)
		}
		obj.Signatures[i] = signatureInfo
	}

	return obj, nil
}

func (ctx *genericSigner) Options() SignerOptions {
	return SignerOptions{
		NonceSource:  ctx.nonceSource,
		EmbedJWK:     ctx.embedJWK,
		ExtraHeaders: ctx.extraHeaders,
	}
}

// Verify validates the signature on the object and returns the payload.
// This function does not support multi-signature. If you desire multi-signature
// verification use VerifyMulti instead.
//
// Be careful when verifying signatures based on embedded JWKs inside the
// payload header. You cannot assume that the key received in a payload is
// trusted.
//
// The verificationKey argument must have one of these types:
//   - ed25519.PublicKey
//   - *mldsa.PublicKey (requires Go 1.27 or later)
//   - *ecdsa.PublicKey
//   - *rsa.PublicKey
//   - *JSONWebKey
//   - JSONWebKey
//   - *JSONWebKeySet
//   - JSONWebKeySet
//   - []byte (an HMAC key)
//   - Any type that implements the OpaqueVerifier interface.
//
// If the key is an HMAC key, it must have at least as many bytes as the relevant hash output:
//   - HS256: 32 bytes
//   - HS384: 48 bytes
//   - HS512: 64 bytes
func (obj JSONWebSignature) Verify(verificationKey any) ([]byte, error) {
	err := obj.DetachedVerify(obj.payload, verificationKey)
	if err != nil {
		return nil, err
	}
	return obj.payload, nil
}

// UnsafePayloadWithoutVerification returns the payload without
// verifying it. The content returned from this function cannot be
// trusted.
func (obj JSONWebSignature) UnsafePayloadWithoutVerification() []byte {
	return obj.payload
}

// DetachedVerify validates a detached signature on the given payload. In
// most cases, you will probably want to use Verify instead. DetachedVerify
// is only useful if you have a payload and signature that are separated from
// each other.
//
// The verificationKey argument must have one of the types allowed for the
// verificationKey argument of JSONWebSignature.Verify().
func (obj JSONWebSignature) DetachedVerify(payload []byte, verificationKey any) error {
	if len(obj.Signatures) != 1 {
		return errors.New("go-jose/go-jose: expecting exactly one signature in payload")
	}

	signature := obj.Signatures[0]

	// The header checks below do not depend on the key, so they run once rather than per candidate key, and
	// their errors reach the caller rather than being flattened into ErrCryptoFailure.
	if signature.header != nil {
		// Per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11,
		// 4.1.11. "crit" (Critical) Header Parameter
		// "When used, this Header Parameter MUST be integrity
		// protected; therefore, it MUST occur only within the JWS
		// Protected Header."
		if err := signature.header.checkNoCritical(); err != nil {
			return err
		}
	}

	if signature.protected != nil {
		if err := signature.protected.checkSupportedCritical(supportedCritical); err != nil {
			return err
		}
	}

	keys, err := tryJWKS(verificationKey, signature.Header, jwkUseSignature)
	if err != nil {
		return err
	}

	input, err := obj.computeAuthData(payload, &signature)
	if err != nil {
		return ErrCryptoFailure
	}

	headers := signature.mergedHeaders()
	alg := headers.getSignatureAlgorithm()

	var (
		usable bool
		errKey error
	)

	// A JWK Set may hold several keys under one "kid", so each candidate is tried before the signature is
	// rejected. Which candidate failed is not reported: that would disclose how the set was searched.
	for _, key := range keys {
		verifier, err := newVerifier(key)
		if err != nil {
			if errKey == nil {
				errKey = err
			}

			continue
		}

		usable = true

		if verifier.verifyPayload(input, signature.Signature, alg) == nil {
			return nil
		}
	}

	// No candidate was a key this package can verify with, which is a caller error worth reporting as itself.
	if !usable {
		return errKey
	}

	return ErrCryptoFailure
}

// VerifyMulti validates (one of the multiple) signatures on the object and
// returns the index of the signature that was verified, along with the signature
// object and the payload. We return the signature and index to guarantee that
// callers are getting the verified value.
//
// The verificationKey argument must have one of the types allowed for the
// verificationKey argument of JSONWebSignature.Verify().
func (obj JSONWebSignature) VerifyMulti(verificationKey any) (int, Signature, []byte, error) {
	idx, sig, err := obj.DetachedVerifyMulti(obj.payload, verificationKey)
	if err != nil {
		return -1, Signature{}, nil, err
	}
	return idx, sig, obj.payload, nil
}

// DetachedVerifyMulti validates a detached signature on the given payload with
// a signature/object that has potentially multiple signers. This returns the index
// of the signature that was verified, along with the signature object. We return
// the signature and index to guarantee that callers are getting the verified value.
//
// In most cases, you will probably want to use Verify or VerifyMulti instead.
// DetachedVerifyMulti is only useful if you have a payload and signature that are
// separated from each other, and the signature can have multiple signers at the
// same time.
//
// The verificationKey argument must have one of the types allowed for the
// verificationKey argument of JSONWebSignature.Verify().
func (obj JSONWebSignature) DetachedVerifyMulti(payload []byte, verificationKey any) (int, Signature, error) {
	for i, signature := range obj.Signatures {
		if signature.header != nil {
			// Per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11,
			// 4.1.11. "crit" (Critical) Header Parameter
			// "When used, this Header Parameter MUST be integrity
			// protected; therefore, it MUST occur only within the JWS
			// Protected Header."
			err := signature.header.checkNoCritical()
			if err != nil {
				continue
			}
		}

		if signature.protected != nil {
			// Check for only supported critical headers
			err := signature.protected.checkSupportedCritical(supportedCritical)
			if err != nil {
				continue
			}
		}

		// If the verification key is a JWK Set, narrow it to the keys this signature's "kid" and "alg"
		// admit. If none match, skip this signature.
		keys, err := tryJWKS(verificationKey, signature.Header, jwkUseSignature)
		if err != nil {
			continue
		}

		input, err := obj.computeAuthData(payload, &signature)
		if err != nil {
			continue
		}

		headers := signature.mergedHeaders()
		alg := headers.getSignatureAlgorithm()

		// One "kid" may name several keys in a set, so every candidate is tried before moving on.
		for _, key := range keys {
			verifier, err := newVerifier(key)
			if err != nil {
				continue
			}

			if verifier.verifyPayload(input, signature.Signature, alg) == nil {
				return i, signature, nil
			}
		}

		continue
	}

	return -1, Signature{}, ErrCryptoFailure
}
