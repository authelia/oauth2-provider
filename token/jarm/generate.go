package jarm

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// EncodeParameters takes the result from jarm.Generate and turns it into parameters in the form of url.Values.
func EncodeParameters(token, _ string, tErr error) (parameters url.Values, err error) {
	if tErr != nil {
		return nil, tErr
	}

	return url.Values{consts.FormParameterResponse: []string{token}}, nil
}

// Generate generates the token and signature for a JARM response.
func Generate(ctx context.Context, config Configurator, client Client, session any, in url.Values) (token, signature string, err error) {
	headers := map[string]any{}

	if alg := client.GetAuthorizationSignedResponseAlg(); len(alg) > 0 {
		headers[consts.JSONWebTokenHeaderAlgorithm] = alg
	}

	if kid := client.GetAuthorizationSignedResponseKeyID(); len(kid) > 0 {
		headers[consts.JSONWebTokenHeaderKeyIdentifier] = kid
	}

	var issuer string

	issuer = config.GetJWTSecuredAuthorizeResponseModeIssuer(ctx)

	if len(issuer) == 0 {
		var (
			src   jwt.MapClaims
			value any
			ok    bool
		)

		switch s := session.(type) {
		case nil:
			return "", "", errors.New("The JARM response modes require the Authorize Requester session to be set but it wasn't.")
		case OpenIDSession:
			src = s.IDTokenClaims().ToMapClaims()
		case JWTSessionContainer:
			src = s.GetJWTClaims().ToMapClaims()
		default:
			return "", "", errors.New("The JARM response modes require the Authorize Requester session to implement either the openid.Session or oauth2.JWTSessionContainer interfaces but it doesn't.")
		}

		if value, ok = src[consts.ClaimIssuer]; ok {
			issuer, _ = value.(string)
		}
	}

	claims := &jwt.JARMClaims{
		JTI:       uuid.New().String(),
		Issuer:    issuer,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(config.GetJWTSecuredAuthorizeResponseModeLifespan(ctx)),
		Audience:  []string{client.GetID()},
		Extra:     map[string]any{},
	}

	for param := range in {
		claims.Extra[param] = in.Get(param)
	}

	var signer jwt.Strategy

	if signer = config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx); signer == nil {
		return "", "", errors.New("The JARM response modes require the JWTSecuredAuthorizeResponseModeSignerProvider to return a jwt.Signer but it didn't.")
	}

	return signer.Encode(ctx, jwt.WithClaims(claims.ToMapClaims()), jwt.WithHeaders(&jwt.Headers{Extra: headers}), jwt.WithJARMClient(client))
}
