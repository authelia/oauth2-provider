package fuzz

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	mrand "math/rand"
	"testing"

	"authelia.com/provider/oauth2/token/jose"
)

var (
	fuzzHMACKey = []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

	fuzzRSAKey  *rsa.PrivateKey
	fuzzECKeys  []*ecdsa.PrivateKey
	fuzzEdKey   ed25519.PrivateKey
	fuzzKeySet  *jose.JSONWebKeySet
	fuzzVerify  []any
	fuzzDecrypt []any
)

func init() {
	deterministic := mrand.New(mrand.NewSource(20260820))

	fuzzRSAKey, _ = rsa.GenerateKey(deterministic, 2048)

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, _ := ecdsa.GenerateKey(curve, deterministic)
		fuzzECKeys = append(fuzzECKeys, key)
	}

	_, fuzzEdKey, _ = ed25519.GenerateKey(deterministic)

	fuzzKeySet = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: fuzzRSAKey.Public(), KeyID: "rsa", Algorithm: string(jose.RS256), Use: "sig"},
			{Key: fuzzECKeys[0].Public(), KeyID: "ec", Algorithm: string(jose.ES256), Use: "sig"},
			{Key: fuzzEdKey.Public(), KeyID: "ed", Algorithm: string(jose.EdDSA), Use: "sig"},
		},
	}

	fuzzVerify = []any{
		fuzzHMACKey,
		fuzzRSAKey.Public(),
		fuzzECKeys[0].Public(),
		fuzzECKeys[1].Public(),
		fuzzECKeys[2].Public(),
		fuzzEdKey.Public(),
		fuzzKeySet,
	}

	fuzzDecrypt = []any{
		fuzzHMACKey,
		fuzzHMACKey[:16],
		fuzzHMACKey[:32],
		fuzzRSAKey,
		fuzzECKeys[0],
		fuzzECKeys[1],
		fuzzECKeys[2],
	}
}

func FuzzJWSVerify(f *testing.F) {
	seedSigned(f)

	f.Add("")
	f.Add("eyJhbGciOiJIUzI1NiJ9..")
	f.Add(`{"payload":"","signatures":[]}`)
	f.Add(`{"payload":"AA","protected":"e30","header":{"alg":"HS256"},"signature":"AA"}`)

	f.Fuzz(func(t *testing.T, token string) {
		obj, err := jose.ParseSigned(token, allSignatureAlgorithms)
		if err != nil {
			return
		}

		for _, key := range fuzzVerify {
			_, _ = obj.Verify(key)
			_, _, _, _ = obj.VerifyMulti(key)
			_ = obj.DetachedVerify([]byte("detached"), key)
		}

		_ = obj.UnsafePayloadWithoutVerification()
		_, _ = obj.CompactSerialize()
		_, _ = obj.DetachedCompactSerialize()
		_ = obj.FullSerialize()
	})
}

func FuzzJWEDecrypt(f *testing.F) {
	for _, alg := range []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW, jose.DIRECT, jose.ECDH_ES, jose.ECDH_ES_A128KW} {
		for _, enc := range allContentEncryption {
			var recipient jose.Recipient

			switch alg {
			case jose.RSA_OAEP_256:
				recipient = jose.Recipient{Algorithm: alg, Key: fuzzRSAKey.Public()}
			case jose.A256KW:
				recipient = jose.Recipient{Algorithm: alg, Key: fuzzHMACKey[:32]}
			case jose.DIRECT:
				continue
			default:
				recipient = jose.Recipient{Algorithm: alg, Key: fuzzECKeys[0].Public()}
			}

			enc, err := jose.NewEncrypter(enc, recipient, nil)
			if err != nil {
				continue
			}

			obj, err := enc.Encrypt([]byte("fuzz"))
			if err != nil {
				continue
			}

			if compact, err := obj.CompactSerialize(); err == nil {
				f.Add(compact)
			}

			f.Add(obj.FullSerialize())
		}
	}

	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AAAAAAAAAAAAAAAAAAAAAA..AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		obj, err := jose.ParseEncrypted(token, allKeyAlgorithms, allContentEncryption)
		if err != nil {
			return
		}

		for _, key := range fuzzDecrypt {
			_, _ = obj.Decrypt(key)
			_, _, _, _ = obj.DecryptMulti(key)
		}

		_ = obj.GetAuthData()
		_, _ = obj.CompactSerialize()
		_ = obj.FullSerialize()
	})
}

func FuzzJWKParse(f *testing.F) {
	f.Add(`{"kty":"oct","k":"AAAA"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`)
	f.Add(`{"kty":"OKP","crv":"Ed25519","x":"AA"}`)
	f.Add(`{"kty":"RSA","n":"AA","e":"AQAB"}`)
	f.Add(`{"keys":[{"kty":"oct","k":"AAAA"}]}`)

	f.Fuzz(func(t *testing.T, raw string) {
		var key jose.JSONWebKey

		if err := key.UnmarshalJSON([]byte(raw)); err == nil {
			_ = key.Valid()
			_ = key.IsPublic()
			_ = key.Public()
			_, _ = key.Thumbprint(crypto.SHA256)
			_, _ = key.MarshalJSON()
		}

		var set jose.JSONWebKeySet

		if err := set.UnmarshalJSON([]byte(raw)); err == nil {
			for _, k := range set.Keys {
				_ = k.Valid()
				_ = k.Public()
				_, _ = k.Thumbprint(crypto.SHA256)
			}
			_ = set.Key("")
		}

		_ = base64.RawURLEncoding
	})
}

func seedSigned(f *testing.F) {
	signers := []jose.SigningKey{
		{Algorithm: jose.HS256, Key: fuzzHMACKey},
		{Algorithm: jose.RS256, Key: fuzzRSAKey},
		{Algorithm: jose.PS512, Key: fuzzRSAKey},
		{Algorithm: jose.ES256, Key: fuzzECKeys[0]},
		{Algorithm: jose.ES384, Key: fuzzECKeys[1]},
		{Algorithm: jose.ES512, Key: fuzzECKeys[2]},
		{Algorithm: jose.EdDSA, Key: fuzzEdKey},
	}

	for _, signingKey := range signers {
		signer, err := jose.NewSigner(signingKey, nil)
		if err != nil {
			continue
		}

		obj, err := signer.Sign([]byte(`{"sub":"fuzz"}`))
		if err != nil {
			continue
		}

		if compact, err := obj.CompactSerialize(); err == nil {
			f.Add(compact)
		}

		f.Add(obj.FullSerialize())
	}
}
