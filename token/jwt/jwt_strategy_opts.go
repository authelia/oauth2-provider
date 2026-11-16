// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"
)

// StrategyOpts holds the options used by the JWT strategy when encoding and decoding tokens.
type StrategyOpts struct {
	client Client

	headers, headersJWE Mapper

	sigAlgorithm      []jose.SignatureAlgorithm
	keyAlgorithm      []jose.KeyAlgorithm
	contentEncryption []jose.ContentEncryption

	jwsKeyFunc KeyFuncJWS
	jweKeyFunc KeyFuncJWE

	allowUnverified    bool
	idTokenHint        bool
	issuerSigningAlg   string
	issuerSigningKeyID string
}

type (
	// KeyFuncJWS resolves the JSON Web Key used to verify a JWS.
	KeyFuncJWS func(ctx context.Context, token *jwt.JSONWebToken, claims MapClaims) (jwk *jose.JSONWebKey, err error)
	// KeyFuncJWE resolves the JSON Web Key used to decrypt a JWE.
	KeyFuncJWE func(ctx context.Context, jwe *jose.JSONWebEncryption, kid, alg string) (jwk *jose.JSONWebKey, err error)
	// StrategyOpt configures StrategyOpts.
	StrategyOpt func(opts *StrategyOpts) (err error)
)

// WithAllowUnverified permits decoding a token without verifying its signature when no client is supplied. The decoded
// token is not marked as having a valid signature.
func WithAllowUnverified() StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.allowUnverified = true

		return nil
	}
}

// WithHeaders sets the JWS headers used when encoding a token.
func WithHeaders(headers Mapper) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.headers = headers

		return nil
	}
}

// WithHeadersJWE sets the JWE headers used when encoding a token which is encrypted.
func WithHeadersJWE(headers Mapper) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.headersJWE = headers

		return nil
	}
}

// WithClient sets the client whose signing and encryption configuration is used.
func WithClient(client Client) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.client = client

		return nil
	}
}

// WithIDTokenClient sets the client using its ID Token signing and encryption configuration. It has no effect when the
// client is not an IDTokenClient.
func WithIDTokenClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(IDTokenClient); ok {
			opts.client = &decoratedIDTokenClient{IDTokenClient: c}
		}

		return nil
	}
}

// WithIDTokenHintClient sets the client as WithIDTokenClient does for decoding an 'id_token_hint'. An ID Token signed
// with the client secret also verifies when the client is registered for that algorithm with no signing key identifier,
// which is the condition Encode signs one under. The client holds that secret and so can forge such a token, which means
// it may only be used for a value which is a hint and never to establish the identity of an End-User.
func WithIDTokenHintClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(IDTokenClient); ok {
			opts.client = &decoratedIDTokenClient{IDTokenClient: c}
			opts.idTokenHint = true
		}

		return nil
	}
}

// WithUserInfoClient sets the client using its UserInfo signing and encryption configuration. It has no effect when the
// client is not a UserInfoClient.
func WithUserInfoClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(UserInfoClient); ok {
			opts.client = &decoratedUserInfoClient{UserInfoClient: c}
		}

		return nil
	}
}

// WithIntrospectionClient sets the client using its Introspection signing and encryption configuration. It has no
// effect when the client is not an IntrospectionClient.
func WithIntrospectionClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(IntrospectionClient); ok {
			opts.client = &decoratedIntrospectionClient{IntrospectionClient: c}
		}

		return nil
	}
}

// WithJARMClient sets the client using its JARM signing and encryption configuration. It has no effect when the client
// is not a JARMClient.
func WithJARMClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(JARMClient); ok {
			opts.client = &decoratedJARMClient{JARMClient: c}
		}

		return nil
	}
}

// WithJARClient sets the client using its JAR signing and encryption configuration. It has no effect when the client is
// not a JARClient.
func WithJARClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(JARClient); ok {
			opts.client = &decoratedJARClient{JARClient: c}
		}

		return nil
	}
}

// WithJWTProfileAccessTokenClient sets the client using its JWT Profile Access Token signing and encryption
// configuration. It has no effect when the client is not a JWTProfileAccessTokenClient.
func WithJWTProfileAccessTokenClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(JWTProfileAccessTokenClient); ok {
			opts.client = &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
		}

		return nil
	}
}

// WithStatelessJWTProfileIntrospectionClient sets the client using its Introspection signing and encryption
// configuration when it is an IntrospectionClient, otherwise its JWT Profile Access Token configuration when it is a
// JWTProfileAccessTokenClient. It has no effect when the client is neither.
func WithStatelessJWTProfileIntrospectionClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		if c, ok := client.(IntrospectionClient); ok {
			opts.client = &decoratedIntrospectionClient{IntrospectionClient: c}
		} else if c, ok := client.(JWTProfileAccessTokenClient); ok {
			opts.client = &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
		}

		return nil
	}
}

// WithSigAlgorithm sets the signature algorithms accepted when decoding a signed token.
func WithSigAlgorithm(algs ...jose.SignatureAlgorithm) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.sigAlgorithm = algs

		return nil
	}
}

// WithKeyAlgorithm sets the key management algorithms accepted when decoding an encrypted token.
func WithKeyAlgorithm(algs ...jose.KeyAlgorithm) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.keyAlgorithm = algs

		return nil
	}
}

// WithContentEncryption sets the content encryption algorithms accepted when decoding an encrypted token.
func WithContentEncryption(enc ...jose.ContentEncryption) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.contentEncryption = enc

		return nil
	}
}

// WithKeyFunc sets the function which returns the key used to verify the signature when decoding a token.
func WithKeyFunc(f KeyFuncJWS) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.jwsKeyFunc = f

		return nil
	}
}

// WithKeyFuncJWE sets the function which returns the key used to decrypt an encrypted token.
func WithKeyFuncJWE(f KeyFuncJWE) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.jweKeyFunc = f

		return nil
	}
}

// WithIssuerSigningAlg selects the issuer key by JWS algorithm when no client is supplied. RS256 is used when alg is
// empty.
func WithIssuerSigningAlg(alg string) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.issuerSigningAlg = alg

		return nil
	}
}

// WithIssuerSigningKeyID selects the issuer key by 'kid' when no client is supplied. The key must have the algorithm
// WithIssuerSigningAlg selects and a 'use' of 'sig', and encoding fails rather than use another key when none matches.
// An empty kid selects the first issuer key for the algorithm.
func WithIssuerSigningKeyID(kid string) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.issuerSigningKeyID = kid

		return nil
	}
}
