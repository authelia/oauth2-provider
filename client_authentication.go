// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	xjwt "github.com/golang-jwt/jwt/v5"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jwt"
)

// ClientAuthenticationStrategy describes a client authentication strategy implementation.
type ClientAuthenticationStrategy interface {
	AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (client Client, method string, err error)
}

type DefaultClientAuthenticationStrategy struct {
	Store interface {
		ClientManager
	}
	Config interface {
		JWKSFetcherStrategyProvider
		TokenURLProvider
	}
}

func (s *DefaultClientAuthenticationStrategy) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (client Client, method string, err error) {
	var (
		id, secret string

		idBasic, secretBasic string

		assertionType, assertion string

		hasPost, hasBasic, hasAssertion bool
	)

	idBasic, secretBasic, hasBasic, err = getClientCredentialsSecretBasic(r)
	if err != nil {
		return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data.").WithWrap(err).WithDebugError(err))
	}

	id, secret, hasPost = s.getClientCredentialsSecretPost(form)
	assertion, assertionType, hasAssertion = getClientCredentialsClientAssertion(form)

	if id, err = getClientCredentialsClientIDValid(id, idBasic, hasAssertion); err != nil {
		return nil, "", err
	}

	// Allow simplification of client authentication.
	if !hasPost && hasBasic {
		secret = secretBasic
	}

	return s.authenticate(ctx, id, secret, assertion, assertionType, hasBasic, hasPost, hasAssertion)
}

func (s *DefaultClientAuthenticationStrategy) authenticate(ctx context.Context, id, secret, assertion, assertionType string, hasBasic, hasPost, hasAssertion bool) (client Client, method string, err error) {
	switch {
	case hasAssertion:
		client, method, err = s.doAuthenticateAssertion(ctx, id, assertion, assertionType)
	case hasBasic, hasPost:
		client, method, err = s.doAuthenticateClientSecret(ctx, id, secret, hasBasic, hasPost)
	default:
		client, method, err = s.doAuthenticateNone(ctx, id)
	}

	if err != nil {
		return nil, "", err
	}

	var methods []string

	if method == consts.ClientAuthMethodNone {
		methods = append(methods, consts.ClientAuthMethodNone)
	}

	if hasBasic {
		methods = append(methods, consts.ClientAuthMethodClientSecretBasic)
	}

	if hasPost {
		methods = append(methods, consts.ClientAuthMethodClientSecretPost)
	}

	if hasAssertion {
		methods = append(methods, fmt.Sprintf("%s (i.e. %s or %s)", consts.ClientAssertionTypeJWTBearer, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodClientSecretJWT))
	}

	return s.handleResolvedClientAuthenticationMethods(ctx, client, method, methods)
}

func (s *DefaultClientAuthenticationStrategy) handleResolvedClientAuthenticationMethods(ctx context.Context, c Client, m string, methods []string) (client Client, method string, err error) {
	switch len(methods) {
	case 0:
		// The 0 case means no authentication information at all exists even if the client is a public client. This
		// likely only occurs on requests where the client_id is not known.
		return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHint("Client Authentication failed with no known authentication method."))
	case 1:
		// Proper authentication has occurred.
		break
	default:
		// The default case handles the situation where a client has leveraged multiple client authentication methods
		// within a request per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3 clients MUST NOT use more than
		// one, however some bad clients use a shotgun approach to authentication. This allows developing a personal
		// policy around these bad clients on a per-client basis.
		if capc, ok := c.(ClientAuthenticationPolicyClient); ok && capc.GetAllowMultipleAuthenticationMethods(ctx) {
			break
		}

		return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHintf("Client Authentication failed with more than one known authentication method included in the request when the authorization server policy does not permit this. The client authentication methods detected were '%s'.", strings.Join(methods, "', '")))
	}

	return c, m, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateNone(ctx context.Context, id string) (client Client, method string, err error) {
	if client, err = s.Store.GetClient(ctx, id); err != nil {
		return nil, "", errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
	}

	if oclient, ok := client.(OpenIDConnectClient); ok {
		if method = oclient.GetTokenEndpointAuthMethod(); method != consts.ClientAuthMethodNone {
			return nil, "", errorsx.WithStack(
				ErrInvalidClient.
					WithHint("The request was determined to be using 'token_endpoint_client_auth_method' method 'none', however the OAuth 2.0 client does not support this method.").
					WithDebugf("The registered client with id '%s' only supports 'token_endpoint_client_auth_method' method '%s'.", client.GetID(), method))
		}
	}

	return client, consts.ClientAuthMethodNone, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateClientSecret(ctx context.Context, id, rawSecret string, hasBasic, hasPost bool) (client Client, method string, err error) {
	if client, err = s.Store.GetClient(ctx, id); err != nil {
		return nil, "", errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
	}

	method = consts.ClientAuthMethodClientSecretBasic

	if !hasBasic && hasPost {
		method = consts.ClientAuthMethodClientSecretPost
	}

	if oclient, ok := client.(OpenIDConnectClient); ok {
		var cmethod string

		if cmethod = oclient.GetTokenEndpointAuthMethod(); cmethod != method {
			return nil, "", errorsx.WithStack(
				ErrInvalidClient.
					WithHintf("The request was determined to be using 'token_endpoint_client_auth_method' method '%s', however the OAuth 2.0 client does not support this method.", method).
					WithDebugf("The registered client with id '%s' only supports 'token_endpoint_client_auth_method' method '%s'.", client.GetID(), cmethod))
		}
	}

	switch err = CompareClientSecret(ctx, client, []byte(rawSecret)); {
	case err == nil:
		return client, method, nil
	case errors.Is(err, ErrClientSecretNotRegistered):
		return nil, "", errorsx.WithStack(
			ErrInvalidClient.
				WithHint("The request was determined to be using 'token_endpoint_client_auth_method' method '%s', however the OAuth 2.0 client does not support this method.").
				WithDebug("The client was not registered with a client secret however this is required to process the particular request."),
		)
	default:
		return nil, "", errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
	}
}

var (
	ErrClientSecretNotRegistered = errors.New("error occurred checking the client secret: the client is not registered with a secret")
)

// CompareClientSecret compares a raw secret input from a client to the registered client secret. If the secret is valid
// it returns nil, otherwise it returns an error. The ErrClientSecretNotRegistered error indicates the ClientSecret
// is nil, all other errors are returned directly from the ClientSecret.Compare function.
func CompareClientSecret(ctx context.Context, client Client, rawSecret []byte) (err error) {
	secret := client.GetClientSecret()

	if secret == nil {
		return ErrClientSecretNotRegistered
	}

	if err = secret.Compare(ctx, rawSecret); err == nil {
		return nil
	}

	var (
		rotated RotatedClientSecretsClient
		ok      bool
	)

	if rotated, ok = client.(RotatedClientSecretsClient); !ok {
		return err
	}

	for _, secret = range rotated.GetRotatedClientSecrets() {
		if secret == nil {
			continue
		}

		if secret.Compare(ctx, rawSecret) == nil {
			return nil
		}
	}

	return err
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertion(ctx context.Context, id, assertion, assertionType string) (client Client, method string, err error) {
	switch assertionType {
	case consts.ClientAssertionTypeJWTBearer:
		if len(assertion) == 0 {
			return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHintf("The client_assertion request parameter must be set when using client_assertion_type of '%s'.", consts.ClientAssertionTypeJWTBearer))
		}

		var (
			token  *xjwt.Token
			claims *xjwt.RegisteredClaims
		)

		if client, method, _, _, token, claims, err = s.doAuthenticateAssertionParseAssertionJWTBearer(ctx, id, assertion); err != nil {
			return nil, "", err
		}

		if token == nil {
			return nil, "", err
		}

		clientID := []byte(client.GetID())

		switch {
		case subtle.ConstantTimeCompare([]byte(claims.Issuer), clientID) == 0:
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
		case subtle.ConstantTimeCompare([]byte(claims.Subject), clientID) == 0:
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
		case claims.ID == "":
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'jti' from 'client_assertion' must be set but is not."))
		default:
			if err = s.Store.ClientAssertionJWTValid(ctx, claims.ID); err != nil {
				return nil, "", errorsx.WithStack(ErrJTIKnown.WithHint("Claim 'jti' from 'client_assertion' MUST only be used once.").WithDebugError(err))
			}

			if err = s.Store.SetClientAssertionJWT(ctx, claims.ID, time.Unix(claims.ExpiresAt.Unix(), 0)); err != nil {
				return nil, "", err
			}

			return client, method, nil
		}
	default:
		return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHintf("Unknown client_assertion_type '%s'.", assertionType))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearer(ctx context.Context, id, assertion string) (client OpenIDConnectClient, method, kid, alg string, token *xjwt.Token, claims *xjwt.RegisteredClaims, err error) {
	var tokenURI string

	if tokenURI = s.Config.GetTokenURL(ctx); tokenURI == "" {
		return nil, "", "", "", nil, nil, errorsx.WithStack(ErrMisconfiguration.WithHint("The authorization server does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods.").WithDebug("The authorization server Token URL was empty but it's required to validate the RFC7523 audience claim."))
	}

	// Automatically satisfies RFC7523 Section 3 Point 5, 8, 9, and 10.
	parser := xjwt.NewParser(
		xjwt.WithStrictDecoding(),
		xjwt.WithAudience(tokenURI),   // Satisfies RFC7523 Section 3 Point 3.
		xjwt.WithExpirationRequired(), // Satisfies RFC7523 Section 3 Point 4.
		xjwt.WithIssuedAt(),           // Satisfies RFC7523 Section 3 Point 6.
	)

	claims = &xjwt.RegisteredClaims{}

	if token, err = parser.ParseWithClaims(assertion, claims, func(token *xjwt.Token) (key any, err error) {
		if id == "" {
			id = claims.Subject
		} else if subtle.ConstantTimeCompare([]byte(id), []byte(claims.Subject)) == 0 {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The supplied 'client_id' did not match the 'sub' claim of the 'client_assertion'."))
		}

		// The following check satisfies RFC7523 Section 3 Point 2.
		// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3.
		if claims.Subject == "" {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The claim 'sub' from the 'client_assertion' isn't defined."))
		}

		var (
			c  Client
			ok bool
		)

		if c, err = s.Store.GetClient(ctx, id); err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
		}

		if client, ok = c.(OpenIDConnectClient); !ok {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The registered client does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods."))
		}

		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKey(ctx, token.Header, client)
	}); err != nil {
		return s.doAuthenticateAssertionParseAssertionJWTBearerParseError(err)
	}

	return client, method, kid, alg, token, claims, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerParseError(uerr error) (client OpenIDConnectClient, method, kid, alg string, token *xjwt.Token, claims *xjwt.RegisteredClaims, err error) {
	var e *RFC6749Error

	switch {
	case errors.As(uerr, &e):
		return nil, "", "", "", nil, nil, errorsx.WithStack(e)
	case errors.Is(uerr, xjwt.ErrTokenMalformed):
		return nil, "", "", "", nil, nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode the 'client_assertion' value as it is malformed or incomplete.").WithWrap(uerr).WithDebugError(uerr))
	case errors.Is(uerr, xjwt.ErrTokenUnverifiable):
		return nil, "", "", "", nil, nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode the 'client_assertion' value as it is missing the information required to validate it.").WithWrap(uerr).WithDebugError(uerr))
	case errors.Is(uerr, xjwt.ErrTokenNotValidYet), errors.Is(uerr, xjwt.ErrTokenExpired), errors.Is(uerr, xjwt.ErrTokenUsedBeforeIssued):
		return nil, "", "", "", nil, nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint.").WithWrap(uerr).WithDebugError(uerr))
	default:
		return nil, "", "", "", nil, nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode 'client_assertion' value for an unknown reason.").WithWrap(uerr).WithDebugError(uerr))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKey(ctx context.Context, header map[string]any, client OpenIDConnectClient) (key any, err error) {
	var kid, alg, method string

	kid, alg = getJWTHeaderKIDAlg(header)

	if client.GetTokenEndpointAuthSigningAlgorithm() != alg {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the token endpoint signing algorithm '%s'.", alg))
	}

	switch method = client.GetTokenEndpointAuthMethod(); method {
	case consts.ClientAuthMethodClientSecretJWT:
		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKeyClientSecretJWT(ctx, kid, alg, client)
	case consts.ClientAuthMethodPrivateKeyJWT:
		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKeyPrivateKeyJWT(ctx, kid, alg, client)
	case consts.ClientAuthMethodNone:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHint("This requested OAuth 2.0 client does not support client authentication, however 'client_assertion' was provided in the request."))
	case consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodClientSecretPost:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however 'client_assertion' was provided in the request.", method))
	default:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however that method is not supported by this server.", method))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKeyClientSecretJWT(_ context.Context, _, alg string, client OpenIDConnectClient) (key any, err error) {
	switch alg {
	case xjwt.SigningMethodHS256.Alg(), xjwt.SigningMethodHS384.Alg(), xjwt.SigningMethodRS512.Alg():
		secret := client.GetClientSecret()

		if secret == nil || !secret.IsPlainText() {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 client does not support the client authentication method 'client_secret_jwt' "))
		}

		if key, err = secret.GetPlainTextValue(); err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 client does not support the client authentication method 'client_secret_jwt' "))
		}

		return key, nil
	default:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the token endpoint signing algorithm '%s'.", alg))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKeyPrivateKeyJWT(ctx context.Context, kid, alg string, client OpenIDConnectClient) (key any, err error) {
	switch alg {
	case xjwt.SigningMethodRS256.Alg(), xjwt.SigningMethodRS384.Alg(), xjwt.SigningMethodRS512.Alg(),
		xjwt.SigningMethodPS256.Alg(), xjwt.SigningMethodPS384.Alg(), xjwt.SigningMethodPS512.Alg(),
		xjwt.SigningMethodES256.Alg(), xjwt.SigningMethodES384.Alg(), xjwt.SigningMethodES512.Alg():
		if key, err = FindClientPublicJWK(ctx, s.Config, client, kid, alg, "sig"); err != nil {
			return nil, err
		}

		return key, nil
	default:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the token endpoint signing algorithm '%s'.", alg))
	}
}

func getClientCredentialsSecretBasic(r *http.Request) (id, secret string, ok bool, err error) {
	auth := r.Header.Get(consts.HeaderAuthorization)

	if auth == "" {
		return "", "", false, nil
	}

	scheme, value, ok := strings.Cut(auth, " ")

	if !ok {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials from the HTTP authorization header could not be parsed.").WithWrap(err).WithDebug("The header value is either missing a scheme, value, or the separator between them."))
	}

	if !strings.EqualFold(scheme, "Basic") {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials from the HTTP authorization header had an unknown scheme.").WithDebugf("The scheme '%s' is not known for client authentication.", scheme))
	}

	c, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials from the HTTP authorization header could not be parsed.").WithWrap(err).WithDebugf("Error occurred performing a base64 decode: %+v.", err))
	}

	cs := string(c)

	id, secret, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials from the HTTP authorization header could not be parsed.").WithDebug("The basic scheme value was not separated by a colon."))
	}

	if id, err = url.QueryUnescape(id); err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client id in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err).WithDebugError(err))
	}

	if secret, err = url.QueryUnescape(secret); err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client secret in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err).WithDebugError(err))
	}

	if len(id) != 0 && !RegexSpecificationVSCHAR.MatchString(id) {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client id in the HTTP request had an invalid character."))
	}

	if len(secret) != 0 && !RegexSpecificationVSCHAR.MatchString(secret) {
		return "", "", false, errorsx.WithStack(ErrInvalidRequest.WithHint("The client secret in the HTTP request had an invalid character."))
	}

	return id, secret, secret != "", nil
}

func (s *DefaultClientAuthenticationStrategy) getClientCredentialsSecretPost(form url.Values) (id, secret string, ok bool) {
	id, secret = form.Get(consts.FormParameterClientID), form.Get(consts.FormParameterClientSecret)

	return id, secret, len(id) != 0 && len(secret) != 0
}

func getJWTHeaderKIDAlg(header map[string]any) (kid, alg string) {
	kid, _ = header[consts.JSONWebTokenHeaderKeyIdentifier].(string)
	alg, _ = header[consts.JSONWebTokenHeaderAlgorithm].(string)

	return kid, alg
}

// FindClientPublicJWK takes a OpenIDConnectClient and a kid, alg, and use to resolve a Public JWK for the client.
func FindClientPublicJWK(ctx context.Context, provider JWKSFetcherStrategyProvider, client OpenIDConnectClient, kid, alg, use string) (key any, err error) {
	if set := client.GetJSONWebKeys(); set != nil {
		return findPublicKeyByKID(kid, alg, use, set)
	}

	strategy := provider.GetJWKSFetcherStrategy(ctx)

	var keys *jose.JSONWebKeySet

	if location := client.GetJSONWebKeysURI(); len(location) > 0 {
		if keys, err = strategy.Resolve(ctx, location, false); err != nil {
			return nil, err
		}

		if key, err = findPublicKeyByKID(kid, alg, use, keys); err == nil {
			return key, nil
		}

		if keys, err = strategy.Resolve(ctx, location, true); err != nil {
			return nil, err
		}

		return findPublicKeyByKID(kid, alg, use, keys)
	}

	return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The OAuth 2.0 Client has no JSON Web Keys set registered, but they are needed to complete the request."))
}

type partial struct {
	points int
	jwk    jose.JSONWebKey
}

func findPublicKeyByKID(kid, alg, use string, set *jose.JSONWebKeySet) (key any, err error) {
	if len(set.Keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The retrieved JSON Web Key Set does not contain any JSON Web Keys."))
	}

	partials := []partial{}

	for _, jwk := range set.Keys {
		if jwk.Use == use && jwk.Algorithm == alg && jwk.KeyID == kid {
			switch k := jwk.Key.(type) {
			case PrivateKey:
				return k.Public(), nil
			default:
				return k, nil
			}
		}

		p := partial{}

		if jwk.KeyID != kid {
			if jwk.KeyID == "" {
				p.points -= 3
			} else {
				continue
			}
		}

		if jwk.Use != use {
			if jwk.Use == "" {
				p.points -= 2
			} else {
				continue
			}
		}

		if jwk.Algorithm != alg && jwk.Algorithm != "" {
			if jwk.Algorithm == "" {
				p.points -= 1
			} else {
				continue
			}
		}

		p.jwk = jwk

		partials = append(partials, p)
	}

	if len(partials) != 0 {
		sort.Slice(partials, func(i, j int) bool {
			return partials[i].points > partials[j].points
		})

		switch k := partials[0].jwk.Key.(type) {
		case PrivateKey:
			return k.Public(), nil
		default:
			return k, nil
		}
	}

	return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to find JWK with kid value '%s', alg value '%s', and use value '%s' in the JSON Web Key Set.", kid, alg, use))
}

// PrivateKey properly describes crypto.PrivateKey.
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

func getClientCredentialsClientAssertion(form url.Values) (assertion, assertionType string, hasAssertion bool) {
	assertionType, assertion = form.Get(consts.FormParameterClientAssertionType), form.Get(consts.FormParameterClientAssertion)

	return assertion, assertionType, len(assertion) != 0 || len(assertionType) != 0
}

func getClientCredentialsClientIDValid(post, header string, assertion bool) (id string, err error) {
	if len(post) != 0 {
		id = post
	} else if len(header) != 0 {
		id = header
	}

	if len(id) == 0 {
		if assertion {
			return id, nil
		}

		return id, errorsx.WithStack(ErrInvalidRequest.WithHint("Client Credentials missing or malformed.").WithDebug("The Client ID was missing from the request but it is required when there is no client assertion."))
	}

	if !RegexSpecificationVSCHAR.MatchString(id) {
		return id, errorsx.WithStack(ErrInvalidRequest.WithHint("The client id in the request had an invalid character."))
	}

	return id, nil
}

type ClientAuthenticationLegacyStrategy func(context.Context, *http.Request, url.Values) (Client, error)

func (f *Fosite) findClientPublicJWK(ctx context.Context, oidcClient OpenIDConnectClient, t *jwt.Token, expectsRSAKey bool) (any, error) {
	if set := oidcClient.GetJSONWebKeys(); set != nil {
		return findPublicKey(t, set, expectsRSAKey)
	}

	if location := oidcClient.GetJSONWebKeysURI(); len(location) > 0 {
		keys, err := f.Config.GetJWKSFetcherStrategy(ctx).Resolve(ctx, location, false)
		if err != nil {
			return nil, err
		}

		if key, err := findPublicKey(t, keys, expectsRSAKey); err == nil {
			return key, nil
		}

		keys, err = f.Config.GetJWKSFetcherStrategy(ctx).Resolve(ctx, location, true)
		if err != nil {
			return nil, err
		}

		return findPublicKey(t, keys, expectsRSAKey)
	}

	return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The OAuth 2.0 Client has no JSON Web Keys set registered, but they are needed to complete the request."))
}

// AuthenticateClient authenticates client requests using the configured strategy returned by the oauth2.Configurator
// function GetClientAuthenticationStrategy, if nil it uses `Fosite.DefaultClientAuthenticationStrategy`.
func (f *Fosite) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (client Client, err error) {
	if strategy := f.Config.GetClientAuthenticationStrategy(ctx); strategy != nil {
		client, _, err = strategy.AuthenticateClient(ctx, r, form)

		return client, err
	}

	return f.DefaultClientAuthenticationStrategy(ctx, r, form)
}

// GetDefaultClientAuthenticationStrategy returns the default ClientAuthenticationStrategy, if nil it initializes one.
func (f *Fosite) GetDefaultClientAuthenticationStrategy(ctx context.Context) ClientAuthenticationStrategy {
	if f.defaultClientAuthenticationStrategy == nil {
		f.defaultClientAuthenticationStrategy = &DefaultClientAuthenticationStrategy{
			f.Store,
			f.Config,
		}
	}

	return f.defaultClientAuthenticationStrategy
}

// DefaultClientAuthenticationStrategy is a helper method to map the legacy method.
func (f *Fosite) DefaultClientAuthenticationStrategy(ctx context.Context, r *http.Request, form url.Values) (client Client, err error) {
	client, _, err = f.GetDefaultClientAuthenticationStrategy(ctx).AuthenticateClient(ctx, r, form)

	return
}

func findPublicKey(t *jwt.Token, set *jose.JSONWebKeySet, expectsRSAKey bool) (any, error) {
	keys := set.Keys
	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The retrieved JSON Web Key Set does not contain any key."))
	}

	kid, ok := t.Header[consts.JSONWebTokenHeaderKeyIdentifier].(string)
	if ok {
		keys = set.Key(kid)
	}

	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The JSON Web Token uses signing key with kid '%s', which could not be found.", kid))
	}

	for _, key := range keys {
		if key.Use != consts.JSONWebTokenUseSignature {
			continue
		}
		if expectsRSAKey {
			if k, ok := key.Key.(*rsa.PublicKey); ok {
				return k, nil
			}
		} else {
			if k, ok := key.Key.(*ecdsa.PublicKey); ok {
				return k, nil
			}
		}
	}

	if expectsRSAKey {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to find RSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	} else {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to find ECDSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	}
}
