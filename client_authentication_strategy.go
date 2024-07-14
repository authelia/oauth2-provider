package oauth2

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	xjwt "github.com/golang-jwt/jwt/v5"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type DefaultClientAuthenticationStrategy struct {
	Store interface {
		ClientManager
	}
	Config interface {
		JWKSFetcherStrategyProvider
		TokenURLProvider
	}
}

func (s *DefaultClientAuthenticationStrategy) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values, resolver EndpointClientAuthHandler) (client Client, method string, err error) {
	var (
		id, secret string

		idBasic, secretBasic string

		assertionValue, assertionType string

		hasPost, hasBasic, hasAssertion bool
	)

	idBasic, secretBasic, hasBasic, err = getClientCredentialsSecretBasic(r)
	if err != nil {
		return nil, "", errorsx.WithStack(ErrInvalidRequest.WithHint("The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data.").WithWrap(err).WithDebugError(err))
	}

	id, secret, hasPost = s.getClientCredentialsSecretPost(form)
	assertionValue, assertionType, hasAssertion = getClientCredentialsClientAssertion(form)

	var assertion *ClientAssertion

	if hasAssertion {
		if assertion, err = NewClientAssertion(ctx, s.Store, assertionValue, assertionType, resolver); err != nil {
			return nil, "", err
		}
	}

	if id, err = getClientCredentialsClientIDValid(id, idBasic, assertion); err != nil {
		return nil, "", err
	}

	// Allow simplification of client authentication.
	if !hasPost && hasBasic {
		secret = secretBasic
	}

	hasNone := !hasPost && !hasBasic && assertion == nil && len(id) != 0

	return s.authenticate(ctx, id, secret, assertion, hasBasic, hasPost, hasNone, resolver)
}

func (s *DefaultClientAuthenticationStrategy) authenticate(ctx context.Context, id, secret string, assertion *ClientAssertion, hasBasic, hasPost, hasNone bool, resolver EndpointClientAuthHandler) (client Client, method string, err error) {
	var methods []string

	if hasBasic {
		methods = append(methods, consts.ClientAuthMethodClientSecretBasic)
	}

	if hasPost {
		methods = append(methods, consts.ClientAuthMethodClientSecretPost)
	}

	if hasNone {
		methods = append(methods, consts.ClientAuthMethodNone)
	}

	if assertion != nil {
		methods = append(methods, fmt.Sprintf("%s (i.e. %s or %s)", consts.ClientAssertionTypeJWTBearer, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodClientSecretJWT))

		if assertion.Client != nil {
			client = assertion.Client
		}
	}

	if client == nil {
		if client, err = s.Store.GetClient(ctx, id); err != nil {
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
		}
	}

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
		if capc, ok := client.(ClientAuthenticationPolicyClient); ok && capc.GetAllowMultipleAuthenticationMethods() {
			break
		}

		return nil, "", errorsx.WithStack(ErrInvalidRequest.
			WithHintf("Client Authentication failed with more than one known authentication method included in the request which is not permitted.").
			WithDebugf("The registered client with id '%s' and the authorization server policy does not permit this malformed request. The `%s_endpoint_auth_method` methods determined to be used were '%s'.", client.GetID(), resolver.Name(), strings.Join(methods, "', '")))
	}

	switch {
	case assertion != nil:
		method, err = s.doAuthenticateAssertionJWTBearer(ctx, client, assertion, resolver)
	case hasBasic, hasPost:
		method, err = s.doAuthenticateClientSecret(ctx, client, secret, hasBasic, hasPost, resolver)
	default:
		method, err = s.doAuthenticateNone(ctx, client, resolver)
	}

	if err != nil {
		return nil, "", err
	}

	return client, method, nil
}

func NewClientAssertion(ctx context.Context, store ClientManager, raw, assertionType string, resolver EndpointClientAuthHandler) (assertion *ClientAssertion, err error) {
	var (
		token *xjwt.Token

		id, alg, method string
		client          Client
	)

	switch assertionType {
	case consts.ClientAssertionTypeJWTBearer:
		if len(raw) == 0 {
			return &ClientAssertion{Raw: raw, Type: assertionType}, errorsx.WithStack(ErrInvalidRequest.WithHintf("The request parameter 'client_assertion' must be set when using 'client_assertion_type' of '%s'.", consts.ClientAssertionTypeJWTBearer))
		}
	default:
		return &ClientAssertion{Raw: raw, Type: assertionType}, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unknown client_assertion_type '%s'.", assertionType))
	}

	if token, _, err = xjwt.NewParser(xjwt.WithoutClaimsValidation()).ParseUnverified(raw, &xjwt.MapClaims{}); err != nil {
		return &ClientAssertion{Raw: raw, Type: assertionType}, resolveJWTErrorToRFCError(err)
	}

	if id, err = token.Claims.GetSubject(); err != nil {
		if id, err = token.Claims.GetIssuer(); err != nil {
			return &ClientAssertion{Raw: raw, Type: assertionType}, nil
		}
	}

	if client, err = store.GetClient(ctx, id); err != nil {
		return &ClientAssertion{Raw: raw, Type: assertionType, ID: id}, nil
	}

	if c, ok := client.(AuthenticationMethodClient); ok {
		alg, method = resolver.GetAuthSigningAlg(c), resolver.GetAuthMethod(c)
	}

	return &ClientAssertion{
		Raw:       raw,
		Type:      assertionType,
		Parsed:    true,
		ID:        id,
		Method:    method,
		Algorithm: alg,
		Client:    client,
	}, nil
}

type ClientAssertion struct {
	Raw, Type             string
	Parsed                bool
	ID, Method, Algorithm string
	Client                Client
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateNone(ctx context.Context, client Client, handler EndpointClientAuthHandler) (method string, err error) {
	if c, ok := client.(AuthenticationMethodClient); ok {
		if method = handler.GetAuthMethod(c); method != consts.ClientAuthMethodNone {
			return "", errorsx.WithStack(
				ErrInvalidClient.
					WithHintf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the OAuth 2.0 client registration does not allow this method.", handler.Name(), consts.ClientAuthMethodNone).
					WithDebugf("The registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s'. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", client.GetID(), handler.Name(), method, handler.Name(), consts.ClientAuthMethodNone, method))
		}
	}

	if !client.IsPublic() {
		return "", errorsx.WithStack(
			ErrInvalidClient.
				WithHintf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the OAuth 2.0 client registration does not allow this method.", consts.ClientAuthMethodNone, handler.Name()).
				WithDebugf("The registered client with id '%s' is configured with a confidential client type but only client registrations with a public client type can use this '%s_endpoint_auth_method'.", client.GetID(), handler.Name()))
	}

	return consts.ClientAuthMethodNone, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateClientSecret(ctx context.Context, client Client, rawSecret string, hasBasic, hasPost bool, handler EndpointClientAuthHandler) (method string, err error) {
	method = consts.ClientAuthMethodClientSecretBasic

	if !hasBasic && hasPost {
		method = consts.ClientAuthMethodClientSecretPost
	}

	if c, ok := client.(AuthenticationMethodClient); ok {
		switch cmethod := handler.GetAuthMethod(c); {
		case cmethod == "" && handler.AllowAuthMethodAny():
			break
		case cmethod != method:
			return "", errorsx.WithStack(
				ErrInvalidClient.
					WithHintf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the OAuth 2.0 client registration does not allow this method.", handler.Name(), method).
					WithDebugf("The registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s'. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", client.GetID(), handler.Name(), cmethod, handler.Name(), method, cmethod))
		}
	}

	switch err = CompareClientSecret(ctx, client, []byte(rawSecret)); {
	case err == nil:
		return method, nil
	case errors.Is(err, ErrClientSecretNotRegistered):
		return "", errorsx.WithStack(
			ErrInvalidClient.
				WithHintf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the OAuth 2.0 client registration does not allow this method.", handler.Name(), method).
				WithDebugf("The registered client with id '%s' has no 'client_secret' however this is required to process the particular request.", client.GetID()),
		)
	default:
		return "", errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionJWTBearer(ctx context.Context, client Client, assertion *ClientAssertion, resolver EndpointClientAuthHandler) (method string, err error) {
	var (
		token  *xjwt.Token
		claims *xjwt.RegisteredClaims
	)

	if method, _, _, token, claims, err = s.doAuthenticateAssertionParseAssertionJWTBearer(ctx, client, assertion, resolver); err != nil {
		return "", err
	}

	if token == nil {
		return "", err
	}

	clientID := []byte(client.GetID())

	switch {
	case subtle.ConstantTimeCompare([]byte(claims.Issuer), clientID) == 0:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case subtle.ConstantTimeCompare([]byte(claims.Subject), clientID) == 0:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case claims.ID == "":
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'jti' from 'client_assertion' must be set but is not."))
	default:
		if err = s.Store.ClientAssertionJWTValid(ctx, claims.ID); err != nil {
			return "", errorsx.WithStack(ErrJTIKnown.WithHint("Claim 'jti' from 'client_assertion' MUST only be used once.").WithDebugError(err))
		}

		if err = s.Store.SetClientAssertionJWT(ctx, claims.ID, time.Unix(claims.ExpiresAt.Unix(), 0)); err != nil {
			return "", err
		}

		return method, nil
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerNew(ctx context.Context, client Client, assertion *ClientAssertion, resolver EndpointClientAuthHandler) (method string, err error) {

}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearer(ctx context.Context, client Client, assertion *ClientAssertion, resolver EndpointClientAuthHandler) (method, kid, alg string, token *xjwt.Token, claims *xjwt.RegisteredClaims, err error) {
	var tokenURI string

	if tokenURI = s.Config.GetTokenURL(ctx); tokenURI == "" {
		return "", "", "", nil, nil, errorsx.WithStack(ErrMisconfiguration.WithHint("The authorization server does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods.").WithDebug("The authorization server Token URL was empty but it's required to validate the RFC7523 audience claim."))
	}

	opts := []xjwt.ParserOption{
		xjwt.WithStrictDecoding(),
		xjwt.WithAudience(tokenURI),   // Satisfies RFC7523 Section 3 Point 3.
		xjwt.WithExpirationRequired(), // Satisfies RFC7523 Section 3 Point 4.
		xjwt.WithIssuedAt(),           // Satisfies RFC7523 Section 3 Point 6.
	}

	// Automatically satisfies RFC7523 Section 3 Point 5, 8, 9, and 10.
	parser := xjwt.NewParser(opts...)

	claims = &xjwt.RegisteredClaims{}

	if token, err = parser.ParseWithClaims(assertion.Raw, claims, func(token *xjwt.Token) (key any, err error) {
		if subtle.ConstantTimeCompare([]byte(client.GetID()), []byte(claims.Subject)) == 0 {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The supplied 'client_id' did not match the 'sub' claim of the 'client_assertion'."))
		}

		// The following check satisfies RFC7523 Section 3 Point 2.
		// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3.
		if claims.Subject == "" {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The claim 'sub' from the 'client_assertion' isn't defined."))
		}

		var (
			c  AuthenticationMethodClient
			ok bool
		)

		if c, ok = client.(AuthenticationMethodClient); !ok {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The registered client does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods."))
		}

		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKey(ctx, token.Header, c, resolver)
	}); err != nil {
		return "", "", "", nil, nil, resolveJWTErrorToRFCError(err)
	}

	return method, kid, alg, token, claims, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKey(ctx context.Context, header map[string]any, client AuthenticationMethodClient, handler EndpointClientAuthHandler) (key any, err error) {
	var kid, alg, method string

	kid, alg = getJWTHeaderKIDAlg(header)

	if calg := handler.GetAuthSigningAlg(client); calg != alg && calg != "" {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the '%s_endpoint_auth_signing_alg' value '%s'.", handler.Name(), alg).WithDebugf("The registered OAuth 2.0 client with id '%s' only supports the '%s' algorithm.", client.GetID(), calg))
	}

	switch method = handler.GetAuthMethod(client); method {
	case consts.ClientAuthMethodClientSecretJWT:
		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKeyClientSecretJWT(ctx, kid, alg, client, handler)
	case consts.ClientAuthMethodPrivateKeyJWT:
		return s.doAuthenticateAssertionParseAssertionJWTBearerFindKeyPrivateKeyJWT(ctx, kid, alg, client, handler)
	case consts.ClientAuthMethodNone:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHint("This requested OAuth 2.0 client does not support client authentication, however 'client_assertion' was provided in the request."))
	case consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodClientSecretPost:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however 'client_assertion' was provided in the request.", method))
	default:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however that method is not supported by this server.", method))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKeyClientSecretJWT(_ context.Context, _, alg string, client AuthenticationMethodClient, handler EndpointClientAuthHandler) (key any, err error) {
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
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the '%s_endpoint_auth_signing_alg' value '%s'.", handler.Name(), alg))
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearerFindKeyPrivateKeyJWT(ctx context.Context, kid, alg string, client AuthenticationMethodClient, handler EndpointClientAuthHandler) (key any, err error) {
	switch alg {
	case xjwt.SigningMethodRS256.Alg(), xjwt.SigningMethodRS384.Alg(), xjwt.SigningMethodRS512.Alg(),
		xjwt.SigningMethodPS256.Alg(), xjwt.SigningMethodPS384.Alg(), xjwt.SigningMethodPS512.Alg(),
		xjwt.SigningMethodES256.Alg(), xjwt.SigningMethodES384.Alg(), xjwt.SigningMethodES512.Alg():
		if key, err = FindClientPublicJWK(ctx, s.Config, client, kid, alg, "sig"); err != nil {
			return nil, err
		}

		return key, nil
	default:
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The requested OAuth 2.0 client does not support the '%s_endpoint_auth_signing_alg' value '%s'.", handler.Name(), alg))
	}
}

func (s *DefaultClientAuthenticationStrategy) getClientCredentialsSecretPost(form url.Values) (id, secret string, ok bool) {
	id, secret = form.Get(consts.FormParameterClientID), form.Get(consts.FormParameterClientSecret)

	return id, secret, len(id) != 0 && len(secret) != 0
}

func resolveJWTErrorToRFCError(err error) (rfc error) {
	var e *RFC6749Error

	switch {
	case errors.As(err, &e):
		return errorsx.WithStack(e)
	case errors.Is(err, xjwt.ErrTokenMalformed):
		return errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode the 'client_assertion' value as it is malformed or incomplete.").WithWrap(err).WithDebugError(err))
	case errors.Is(err, xjwt.ErrTokenUnverifiable):
		return errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode the 'client_assertion' value as it is missing the information required to validate it.").WithWrap(err).WithDebugError(err))
	case errors.Is(err, xjwt.ErrTokenNotValidYet), errors.Is(err, xjwt.ErrTokenExpired), errors.Is(err, xjwt.ErrTokenUsedBeforeIssued):
		return errorsx.WithStack(ErrInvalidClient.WithHint("Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint.").WithWrap(err).WithDebugError(err))
	default:
		return errorsx.WithStack(ErrInvalidClient.WithHint("Unable to decode 'client_assertion' value for an unknown reason.").WithWrap(err).WithDebugError(err))
	}
}
