package jwt

import (
	"context"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type StrategyOpts struct {
	client Client

	headers, headersJWE Mapper

	sigAlgorithm      []jose.SignatureAlgorithm
	keyAlgorithm      []jose.KeyAlgorithm
	contentEncryption []jose.ContentEncryption

	jwsKeyFunc KeyFuncJWS
	jweKeyFunc KeyFuncJWE

	allowUnverified bool
}

type (
	KeyFuncJWS  func(ctx context.Context, token *jwt.JSONWebToken, claims MapClaims) (jwk *jose.JSONWebKey, err error)
	KeyFuncJWE  func(ctx context.Context, jwe *jose.JSONWebEncryption, kid, alg string) (jwk *jose.JSONWebKey, err error)
	StrategyOpt func(opts *StrategyOpts) (err error)
)

func WithAllowUnverified() StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.allowUnverified = true

		return nil
	}
}

func WithHeaders(headers Mapper) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.headers = headers

		return nil
	}
}

func WithHeadersJWE(headers Mapper) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.headersJWE = headers

		return nil
	}
}

func WithClient(client Client) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.client = client

		return nil
	}
}

func WithIDTokenClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case IDTokenClient:
			opts.client = &decoratedIDTokenClient{IDTokenClient: c}
		}

		return nil
	}
}

func WithUserInfoClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case UserInfoClient:
			opts.client = &decoratedUserInfoClient{UserInfoClient: c}
		}

		return nil
	}
}

func WithIntrospectionClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case IntrospectionClient:
			opts.client = &decoratedIntrospectionClient{IntrospectionClient: c}
		}

		return nil
	}
}

func WithJARMClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case JARMClient:
			opts.client = &decoratedJARMClient{JARMClient: c}
		}

		return nil
	}
}

func WithJARClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case JARClient:
			opts.client = &decoratedJARClient{JARClient: c}
		}

		return nil
	}
}

func WithJWTProfileAccessTokenClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case JWTProfileAccessTokenClient:
			opts.client = &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
		}

		return nil
	}
}

func WithStatelessJWTProfileIntrospectionClient(client any) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		switch c := client.(type) {
		case IntrospectionClient:
			opts.client = &decoratedIntrospectionClient{IntrospectionClient: c}
		case JWTProfileAccessTokenClient:
			opts.client = &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
		}

		return nil
	}
}

func WithSigAlgorithm(algs ...jose.SignatureAlgorithm) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.sigAlgorithm = algs

		return nil
	}
}

func WithKeyAlgorithm(algs ...jose.KeyAlgorithm) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.keyAlgorithm = algs

		return nil
	}
}

func WithContentEncryption(enc ...jose.ContentEncryption) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.contentEncryption = enc

		return nil
	}
}

func WithKeyFunc(f KeyFuncJWS) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.jwsKeyFunc = f

		return nil
	}
}

func WithKeyFuncJWE(f KeyFuncJWE) StrategyOpt {
	return func(opts *StrategyOpts) (err error) {
		opts.jweKeyFunc = f

		return nil
	}
}
