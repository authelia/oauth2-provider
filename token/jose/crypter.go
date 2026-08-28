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
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"authelia.com/provider/oauth2/token/jose/json"
)

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter interface {
	Encrypt(plaintext []byte) (*JSONWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JSONWebEncryption, error)
	Options() EncrypterOptions
}

// A generic content cipher
type contentCipher interface {
	keySize() int
	encrypt(cek []byte, aad, plaintext []byte) (*aeadParts, error)
	decrypt(cek []byte, aad []byte, parts *aeadParts) ([]byte, error)
}

// A key generator (for generating/getting a CEK)
type keyGenerator interface {
	keySize() int
	genKey() ([]byte, rawHeader, error)
}

// A generic key encrypter
type keyEncrypter interface {
	encryptKey(cek []byte, alg KeyAlgorithm) (recipientInfo, error) // Encrypt a key
}

// A generic key decrypter
type keyDecrypter interface {
	decryptKey(headers rawHeader, recipient *recipientInfo, generator keyGenerator) ([]byte, error) // Decrypt a key
}

// A generic encrypter based on the given key encrypter and content cipher.
type genericEncrypter struct {
	contentAlg     ContentEncryption
	compressionAlg CompressionAlgorithm
	cipher         contentCipher
	recipients     []recipientKeyInfo
	keyGenerator   keyGenerator
	extraHeaders   map[HeaderKey]any
	apuData        []byte
	apvData        []byte
}

// ecdhPartyInfo extracts the ECDH-ES PartyUInfo and PartyVInfo values from the
// caller's extra headers.
//
// RFC 7518 Section 4.6.2 makes "apu" and "apv" inputs to the Concat KDF, so
// they have to be known before the key is derived, whereas extra headers are
// otherwise only written to the protected header afterwards. Decoding reuses
// the byteBuffer the decrypter applies to the parsed header, so the two sides
// cannot disagree about how a value is interpreted.
func ecdhPartyInfo(extraHeaders map[HeaderKey]any) (apuData, apvData []byte, err error) {
	if apuData, err = extraHeaderBytes(extraHeaders, headerAPU); err != nil {
		return nil, nil, err
	}

	if apvData, err = extraHeaderBytes(extraHeaders, headerAPV); err != nil {
		return nil, nil, err
	}

	return apuData, apvData, nil
}

// extraHeaderBytes decodes a base64url header value supplied through extra headers.
func extraHeaderBytes(extraHeaders map[HeaderKey]any, k HeaderKey) ([]byte, error) {
	value, ok := extraHeaders[k]
	if !ok || value == nil {
		return nil, nil
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid %q header: %w", string(k), err)
	}

	var buffer *byteBuffer

	if err = json.Unmarshal(raw, &buffer); err != nil {
		return nil, fmt.Errorf("go-jose/go-jose: invalid %q header, must be a base64url encoded string: %w", string(k), err)
	}

	return buffer.bytes(), nil
}

type recipientKeyInfo struct {
	keyID        string
	keyAlg       KeyAlgorithm
	keyEncrypter keyEncrypter
}

// EncrypterOptions represents options that can be set on new encrypters.
type EncrypterOptions struct {
	Compression CompressionAlgorithm

	// Optional map of name/value pairs to be inserted into the protected
	// header of a JWS object. Some specifications which make use of
	// JWS require additional values here.
	//
	// Values will be serialized by [json.Marshal] and must be valid inputs to
	// that function.
	//
	// These are written over the protected header the encrypter assembles, so
	// "enc", "zip" and "alg" are rejected by [NewEncrypter] and
	// [NewMultiEncrypter]: the first two come from the arguments to those calls
	// and the third from the recipient, and a value supplied here would describe
	// an operation other than the one performed. Use the Compression field for
	// "zip". "cty", "typ", "kid" and any extension parameter are the caller's to
	// set, as are "apu" and "apv", which ECDH-ES reads from this map.
	//
	// [json.Marshal]: https://pkg.go.dev/encoding/json#Marshal
	ExtraHeaders map[HeaderKey]any
}

// WithHeader adds an arbitrary value to the ExtraHeaders map, initializing it
// if necessary, and returns the updated EncrypterOptions.
//
// The v parameter will be serialized by [json.Marshal] and must be a valid
// input to that function.
//
// [json.Marshal]: https://pkg.go.dev/encoding/json#Marshal
func (eo *EncrypterOptions) WithHeader(k HeaderKey, v any) *EncrypterOptions {
	if eo.ExtraHeaders == nil {
		eo.ExtraHeaders = map[HeaderKey]any{}
	}
	eo.ExtraHeaders[k] = v
	return eo
}

// WithContentType adds a content type ("cty") header and returns the updated
// EncrypterOptions.
func (eo *EncrypterOptions) WithContentType(contentType ContentType) *EncrypterOptions {
	return eo.WithHeader(HeaderContentType, contentType)
}

// WithType adds a type ("typ") header and returns the updated EncrypterOptions.
func (eo *EncrypterOptions) WithType(typ ContentType) *EncrypterOptions {
	return eo.WithHeader(HeaderType, typ)
}

// Recipient represents an algorithm/key to encrypt messages to.
//
// PBES2Count and PBES2Salt correspond with the  "p2c" and "p2s" headers used
// on the password-based encryption algorithms PBES2-HS256+A128KW,
// PBES2-HS384+A192KW, and PBES2-HS512+A256KW. If they are not provided a safe
// default of 100000 will be used for the count and a 128-bit random salt will
// be generated. An [OpaqueKeyEncrypter] derives the key itself and cannot apply
// either, so supplying them alongside one is an error rather than a request
// this package can meet.
type Recipient struct {
	Algorithm KeyAlgorithm
	// Key must have one of these types:
	//  - ed25519.PublicKey
	//  - *ecdsa.PublicKey
	//  - *rsa.PublicKey
	//  - *JSONWebKey
	//  - JSONWebKey
	//  - []byte (a symmetric key)
	//  - Any type that satisfies the OpaqueKeyEncrypter interface
	//
	// The type of Key must match the value of Algorithm.
	Key        any
	KeyID      string
	PBES2Count int
	PBES2Salt  []byte
}

// NewEncrypter creates an appropriate encrypter based on the key type
func NewEncrypter(enc ContentEncryption, rcpt Recipient, opts *EncrypterOptions) (Encrypter, error) {
	encrypter := &genericEncrypter{
		contentAlg: enc,
		recipients: []recipientKeyInfo{},
		cipher:     getContentCipher(enc),
	}
	if opts != nil {
		encrypter.compressionAlg = opts.Compression
		encrypter.extraHeaders = opts.ExtraHeaders

		// "enc" and "zip" are written into the protected header from the arguments to this call, and "alg" into
		// each recipient header from the recipient itself.
		if err := checkExtraHeaders(encrypter.extraHeaders, headerAlgorithm, headerEncryption, headerCompression); err != nil {
			return nil, err
		}
	}

	if encrypter.cipher == nil {
		return nil, ErrUnsupportedAlgorithm
	}

	var err error

	if encrypter.apuData, encrypter.apvData, err = ecdhPartyInfo(encrypter.extraHeaders); err != nil {
		return nil, err
	}

	var keyID string
	var rawKey any
	switch encryptionKey := rcpt.Key.(type) {
	case JSONWebKey:
		keyID, rawKey = encryptionKey.KeyID, encryptionKey.Key
	case *JSONWebKey:
		keyID, rawKey = encryptionKey.KeyID, encryptionKey.Key
	case OpaqueKeyEncrypter:
		keyID, rawKey = encryptionKey.KeyID(), encryptionKey
	default:
		rawKey = encryptionKey
	}

	switch rcpt.Algorithm {
	case DIRECT:
		// Direct encryption mode must be treated differently
		keyBytes, ok := rawKey.([]byte)
		if !ok {
			return nil, ErrUnsupportedKeyType
		}
		if encrypter.cipher.keySize() != len(keyBytes) {
			return nil, ErrInvalidKeySize
		}
		encrypter.keyGenerator = staticKeyGenerator{
			key: keyBytes,
		}
		recipientInfo, _ := newSymmetricRecipient(rcpt.Algorithm, keyBytes)
		recipientInfo.keyID = keyID
		if rcpt.KeyID != "" {
			recipientInfo.keyID = rcpt.KeyID
		}
		encrypter.recipients = []recipientKeyInfo{recipientInfo}
		return encrypter, nil
	case ECDH_ES:
		// ECDH-ES (w/o key wrapping) is similar to DIRECT mode
		keyDSA, ok := rawKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrUnsupportedKeyType
		}
		encrypter.keyGenerator = ecKeyGenerator{
			size:      encrypter.cipher.keySize(),
			algID:     string(enc),
			apuData:   encrypter.apuData,
			apvData:   encrypter.apvData,
			publicKey: keyDSA,
		}
		recipientInfo, _ := newECDHRecipient(rcpt.Algorithm, keyDSA)
		recipientInfo.keyID = keyID
		if rcpt.KeyID != "" {
			recipientInfo.keyID = rcpt.KeyID
		}
		encrypter.recipients = []recipientKeyInfo{recipientInfo}
		return encrypter, nil
	default:
		// Can just add a standard recipient
		encrypter.keyGenerator = randomKeyGenerator{
			size: encrypter.cipher.keySize(),
		}
		err = encrypter.addRecipient(rcpt)
		return encrypter, err
	}
}

// NewMultiEncrypter creates a multi-encrypter based on the given parameters
func NewMultiEncrypter(enc ContentEncryption, rcpts []Recipient, opts *EncrypterOptions) (Encrypter, error) {
	cipher := getContentCipher(enc)

	if cipher == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	if len(rcpts) == 0 {
		return nil, fmt.Errorf("go-jose/go-jose: recipients is nil or empty")
	}

	encrypter := &genericEncrypter{
		contentAlg: enc,
		recipients: []recipientKeyInfo{},
		cipher:     cipher,
		keyGenerator: randomKeyGenerator{
			size: cipher.keySize(),
		},
	}

	if opts != nil {
		encrypter.compressionAlg = opts.Compression
		encrypter.extraHeaders = opts.ExtraHeaders

		// "enc" and "zip" are written into the protected header from the arguments to this call, and "alg" into
		// each recipient header from the recipient itself.
		if err := checkExtraHeaders(encrypter.extraHeaders, headerAlgorithm, headerEncryption, headerCompression); err != nil {
			return nil, err
		}
	}

	var err error

	if encrypter.apuData, encrypter.apvData, err = ecdhPartyInfo(encrypter.extraHeaders); err != nil {
		return nil, err
	}

	for _, recipient := range rcpts {
		if err = encrypter.addRecipient(recipient); err != nil {
			return nil, err
		}
	}

	return encrypter, nil
}

func (ctx *genericEncrypter) addRecipient(recipient Recipient) (err error) {
	var recipientInfo recipientKeyInfo

	switch recipient.Algorithm {
	case DIRECT, ECDH_ES:
		return fmt.Errorf("go-jose/go-jose: key algorithm '%s' not supported in multi-recipient mode", recipient.Algorithm)
	}

	recipientInfo, err = makeJWERecipient(recipient.Algorithm, recipient.Key)
	if err != nil {
		return err
	}

	if recipient.KeyID != "" {
		recipientInfo.keyID = recipient.KeyID
	}

	// These parameters reach the key encrypter by type assertion, and an OpaqueKeyEncrypter satisfies neither
	// assertion: it derives or wraps the key itself. Supplying them anyway used to discard them without a word,
	// leaving a message encrypted under defaults, or a header advertising party information the key derivation
	// never saw. A caller which supplied nothing is unaffected, since there is then nothing to discard.
	switch recipient.Algorithm {
	case PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW:
		sr, ok := recipientInfo.keyEncrypter.(*symmetricKeyCipher)
		if !ok {
			if recipient.PBES2Count != 0 || len(recipient.PBES2Salt) != 0 {
				return fmt.Errorf("%w: %T cannot apply PBES2Count or PBES2Salt", ErrUnsupportedRecipientParameter, recipientInfo.keyEncrypter)
			}

			break
		}

		sr.p2c = recipient.PBES2Count
		sr.p2s = recipient.PBES2Salt
	case ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
		er, ok := recipientInfo.keyEncrypter.(*ecEncrypterVerifier)
		if !ok {
			if len(ctx.apuData) != 0 || len(ctx.apvData) != 0 {
				return fmt.Errorf("%w: %T cannot apply the apu or apv header parameter", ErrUnsupportedRecipientParameter, recipientInfo.keyEncrypter)
			}

			break
		}

		er.apuData = ctx.apuData
		er.apvData = ctx.apvData
	}

	ctx.recipients = append(ctx.recipients, recipientInfo)
	return nil
}

func makeJWERecipient(alg KeyAlgorithm, encryptionKey any) (recipientKeyInfo, error) {
	switch encryptionKey := encryptionKey.(type) {
	case *rsa.PublicKey:
		return newRSARecipient(alg, encryptionKey)
	case *ecdsa.PublicKey:
		return newECDHRecipient(alg, encryptionKey)
	case []byte:
		return newSymmetricRecipient(alg, encryptionKey)
	case string:
		return newSymmetricRecipient(alg, []byte(encryptionKey))
	case JSONWebKey:
		recipient, err := makeJWERecipient(alg, encryptionKey.Key)
		recipient.keyID = encryptionKey.KeyID
		return recipient, err
	case *JSONWebKey:
		recipient, err := makeJWERecipient(alg, encryptionKey.Key)
		recipient.keyID = encryptionKey.KeyID
		return recipient, err
	case OpaqueKeyEncrypter:
		return newOpaqueKeyEncrypter(alg, encryptionKey)
	}
	return recipientKeyInfo{}, ErrUnsupportedKeyType
}

// newDecrypter creates an appropriate decrypter based on the key type
func newDecrypter(decryptionKey any) (keyDecrypter, error) {
	switch decryptionKey := decryptionKey.(type) {
	case *rsa.PrivateKey:
		return &rsaDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case *ecdsa.PrivateKey:
		return &ecDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case []byte:
		return &symmetricKeyCipher{
			key: decryptionKey,
		}, nil
	case string:
		return &symmetricKeyCipher{
			key: []byte(decryptionKey),
		}, nil
	case JSONWebKey:
		return newDecrypter(decryptionKey.Key)
	case *JSONWebKey:
		return newDecrypter(decryptionKey.Key)
	case OpaqueKeyDecrypter:
		return &opaqueKeyDecrypter{decrypter: decryptionKey}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// Implementation of encrypt method producing a JWE object.
func (ctx *genericEncrypter) Encrypt(plaintext []byte) (*JSONWebEncryption, error) {
	return ctx.EncryptWithAuthData(plaintext, nil)
}

// Implementation of encrypt method producing a JWE object.
func (ctx *genericEncrypter) EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error) {
	obj := &JSONWebEncryption{}
	obj.aad = aad

	obj.protected = &rawHeader{}
	err := obj.protected.set(headerEncryption, ctx.contentAlg)
	if err != nil {
		return nil, err
	}

	obj.recipients = make([]recipientInfo, len(ctx.recipients))

	if len(ctx.recipients) == 0 {
		return nil, fmt.Errorf("go-jose/go-jose: no recipients to encrypt to")
	}

	cek, headers, err := ctx.keyGenerator.genKey()
	if err != nil {
		return nil, err
	}

	obj.protected.merge(&headers)

	for i, info := range ctx.recipients {
		recipient, err := info.keyEncrypter.encryptKey(cek, info.keyAlg)
		if err != nil {
			return nil, err
		}

		err = recipient.header.set(headerAlgorithm, info.keyAlg)
		if err != nil {
			return nil, err
		}

		if info.keyID != "" {
			err = recipient.header.set(headerKeyID, info.keyID)
			if err != nil {
				return nil, err
			}
		}
		obj.recipients[i] = recipient
	}

	if len(ctx.recipients) == 1 {
		// Move per-recipient headers into main protected header if there's
		// only a single recipient.
		obj.protected.merge(obj.recipients[0].header)
		obj.recipients[0].header = nil
	}

	if ctx.compressionAlg != NONE {
		plaintext, err = compress(ctx.compressionAlg, plaintext)
		if err != nil {
			return nil, err
		}

		err = obj.protected.set(headerCompression, ctx.compressionAlg)
		if err != nil {
			return nil, err
		}
	}

	for k, v := range ctx.extraHeaders {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		(*obj.protected)[k] = makeRawMessage(b)
	}

	// Extra headers land in the protected header after the per-recipient headers
	// are built, so a caller setting one that a recipient also carries would
	// otherwise emit a JWE whose header names are not disjoint. RFC 7516 Section
	// 7.2.1 forbids that, and this package now rejects it on the way back in, so
	// fail here rather than produce something nothing can read.
	for i := range obj.recipients {
		if err = checkDisjoint(obj.protected, obj.recipients[i].header); err != nil {
			return nil, fmt.Errorf("go-jose/go-jose: recipient %d: %w", i, err)
		}
	}

	authData := obj.computeAuthData()
	parts, err := ctx.cipher.encrypt(cek, authData, plaintext)
	if err != nil {
		return nil, err
	}

	obj.iv = parts.iv
	obj.ciphertext = parts.ciphertext
	obj.tag = parts.tag

	return obj, nil
}

func (ctx *genericEncrypter) Options() EncrypterOptions {
	return EncrypterOptions{
		Compression:  ctx.compressionAlg,
		ExtraHeaders: ctx.extraHeaders,
	}
}

// Decrypt and validate the object and return the plaintext. This
// function does not support multi-recipient. If you desire multi-recipient
// decryption use DecryptMulti instead.
//
// The decryptionKey argument must contain a private or symmetric key
// and must have one of these types:
//   - *ecdsa.PrivateKey
//   - *rsa.PrivateKey
//   - *JSONWebKey
//   - JSONWebKey
//   - *JSONWebKeySet
//   - JSONWebKeySet
//   - []byte (a symmetric key)
//   - string (a symmetric key)
//   - Any type that satisfies the OpaqueKeyDecrypter interface.
//
// Note that ed25519 is only available for signatures, not encryption, so is
// not an option here.
//
// Automatically decompresses plaintext, but returns an error if the decompressed
// data would be >250kB or >10x the size of the compressed data, whichever is larger.
func (obj JSONWebEncryption) Decrypt(decryptionKey any) ([]byte, error) {
	headers := obj.mergedHeaders(nil)

	if len(obj.recipients) > 1 {
		return nil, errors.New("go-jose/go-jose: too many recipients in payload; expecting only one")
	}

	err := headers.checkNoCritical()
	if err != nil {
		return nil, err
	}

	keys, err := tryJWKS(decryptionKey, Header{
		KeyID:     headers.getString(headerKeyID),
		Algorithm: headers.getString(headerAlgorithm),
	}, jwkUseEncryption)
	if err != nil {
		return nil, err
	}

	cipher := getContentCipher(headers.getEncryption())
	if cipher == nil {
		return nil, fmt.Errorf("go-jose/go-jose: unsupported enc value '%s'", string(headers.getEncryption()))
	}

	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}

	authData := obj.computeAuthData()

	recipient := obj.recipients[0]
	recipientHeaders := obj.mergedHeaders(&recipient)

	var (
		plaintext []byte
		usable    bool
		decrypted bool
		errKey    error
	)

	// A JWK Set may hold several keys under one "kid", so each candidate is tried before the message is
	// rejected. Which candidate failed is not reported: that would disclose how the set was searched.
	for _, key := range keys {
		decrypter, err := newDecrypter(key)
		if err != nil {
			if errKey == nil {
				errKey = err
			}

			continue
		}

		usable = true

		cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
		if err != nil {
			continue
		}

		if err = validateCEKSize(cek, cipher); err != nil {
			continue
		}

		// Found a valid CEK -- let's try to decrypt. An empty plaintext is a valid result, so success is
		// tracked separately rather than inferred from the plaintext being non-empty.
		if plaintext, err = cipher.decrypt(cek, authData, parts); err == nil {
			decrypted = true

			break
		}
	}

	// No candidate was a key this package can decrypt with, which is a caller error worth reporting as itself.
	if !usable {
		return nil, errKey
	}

	if !decrypted {
		return nil, ErrCryptoFailure
	}

	plaintext, err = obj.decompress(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptMulti decrypts and validates the object and returns the plaintexts,
// with support for multiple recipients. It returns the index of the recipient
// for which the decryption was successful, the caller-visible headers for that
// recipient, and the plaintext.
//
// The decryptionKey argument must have one of the types allowed for the
// decryptionKey argument of Decrypt().
//
// Automatically decompresses plaintext, but returns an error if the decompressed
// data would be >250kB or >3x the size of the compressed data, whichever is larger.
func (obj JSONWebEncryption) DecryptMulti(decryptionKey any) (int, Header, []byte, error) {
	globalHeaders := obj.mergedHeaders(nil)

	err := globalHeaders.checkNoCritical()
	if err != nil {
		return -1, Header{}, nil, err
	}

	encryption := globalHeaders.getEncryption()
	cipher := getContentCipher(encryption)
	if cipher == nil {
		return -1, Header{}, nil, fmt.Errorf("go-jose/go-jose: unsupported enc value '%s'", string(encryption))
	}

	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}

	authData := obj.computeAuthData()

	index := -1
	var plaintext []byte
	var headers rawHeader

	if len(obj.recipients) == 0 {
		return -1, Header{}, nil, errors.New("go-jose/go-jose: no recipients")
	}

	var (
		usable  bool
		errKey  error
		errJWKS error
	)

	// "kid" and "alg" are written into each recipient's own header, so the key is selected per recipient rather
	// than once for the message: a multi-recipient JWE carries neither globally. A JWK Set may then hold several
	// keys under one "kid", so each candidate is tried before the recipient is given up on.
	for i := range obj.recipients {
		recipient := obj.recipients[i]
		recipientHeaders := obj.mergedHeaders(&recipient)

		keys, err := tryJWKS(decryptionKey, Header{
			KeyID:     recipientHeaders.getString(headerKeyID),
			Algorithm: recipientHeaders.getString(headerAlgorithm),
		}, jwkUseEncryption)
		if err != nil {
			// The set holds nothing for this recipient. Another recipient may still be ours.
			if errJWKS == nil {
				errJWKS = err
			}

			continue
		}

		for _, key := range keys {
			decrypter, err := newDecrypter(key)
			if err != nil {
				if errKey == nil {
					errKey = err
				}

				continue
			}

			usable = true

			cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
			if err != nil {
				continue
			}

			if err = validateCEKSize(cek, cipher); err != nil {
				continue
			}

			// Found a valid CEK -- let's try to decrypt. An empty plaintext is a valid result, so the recipient
			// index tracks success rather than the plaintext being non-empty.
			decrypted, err := cipher.decrypt(cek, authData, parts)
			if err != nil {
				continue
			}

			plaintext = decrypted
			index = i
			headers = obj.publicHeaders(&obj.recipients[i])

			break
		}

		if index >= 0 {
			break
		}
	}

	if index < 0 {
		// No candidate was a key this package can decrypt with, which is a caller error worth reporting as
		// itself. Failing that, no recipient named a key the set holds, which is a fact about the set rather
		// than about the message and is reported the same way Decrypt reports it.
		switch {
		case usable:
			// Something was tried against the message and did not work; which candidate got furthest is not
			// reported, as that would disclose how the set was searched.
			return -1, Header{}, nil, ErrCryptoFailure
		case errKey != nil:
			return -1, Header{}, nil, errKey
		case errJWKS != nil:
			return -1, Header{}, nil, errJWKS
		default:
			return -1, Header{}, nil, ErrCryptoFailure
		}
	}

	plaintext, err = obj.decompress(plaintext)
	if err != nil {
		return -1, Header{}, nil, err
	}

	sanitized, err := headers.sanitized()
	if err != nil {
		return -1, Header{}, nil, fmt.Errorf("go-jose/go-jose: failed to sanitize header: %v", err)
	}

	return index, sanitized, plaintext, nil
}

// decompress decompresses plaintext using the protected "zip" header, if present.
// It returns plaintext unchanged when there is no protected header or "zip" value.
func (obj JSONWebEncryption) decompress(plaintext []byte) ([]byte, error) {
	if obj.protected == nil {
		return plaintext, nil
	}

	comp := obj.protected.getCompression()
	if comp == "" {
		return plaintext, nil
	}

	plaintext, err := decompress(comp, plaintext)
	if err != nil {
		return nil, fmt.Errorf("go-jose/go-jose: failed to decompress plaintext: %v", err)
	}
	return plaintext, nil
}

func validateCEKSize(cek []byte, cipher contentCipher) (err error) {
	if len(cek) != cipher.keySize() {
		return ErrInvalidKeySize
	}

	return nil
}
