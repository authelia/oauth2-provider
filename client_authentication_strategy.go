// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type DefaultClientAuthenticationStrategy struct {
	Store interface {
		ClientManager
	}
	Config interface {
		JWTStrategyProvider
		JWKSFetcherStrategyProvider
		AllowedJWTAssertionAudiencesProvider
		ClientAssertionClientSecretEncryptionDisabledProvider
		JWTClockSkewProvider
		MTLSConfigProvider
	}
}

// AuthenticateClient authenticates the client making the request using the credentials presented in the 'Authorization'
// header, the form, a client assertion, and when mutual TLS is enabled the client certificate. It returns the client
// and the authentication method used.
func (s *DefaultClientAuthenticationStrategy) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values, strategy EndpointClientAuthStrategy) (client Client, method string, err error) {
	var (
		id, secretPost string

		idBasic, secretBasic string

		assertionValue, assertionType string

		hasPost, hasBasic, hasAssertion bool
	)

	idBasic, secretBasic, hasBasic, err = getClientCredentialsSecretBasic(r)
	if err != nil {
		return nil, "", err
	}

	id, secretPost, hasPost = s.getClientCredentialsSecretPost(form)
	assertionValue, assertionType, hasAssertion = getClientCredentialsClientAssertion(form)

	var assertion *ClientAssertion

	if hasAssertion {
		if assertion, err = s.newClientAssertion(ctx, id, assertionValue, assertionType, strategy); err != nil {
			return nil, "", err
		}
	}

	if id, err = getClientCredentialsClientIDValid(id, idBasic, assertion); err != nil {
		return nil, "", err
	}

	var (
		cert     *x509.Certificate
		verified bool
	)

	if s.Config.GetMTLSEnabled(ctx) {
		header := s.Config.GetMTLSClientCertificateHeader(ctx)

		if cert, err = ClientCertificateFromRequest(r, header); err != nil {
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithWrap(err).WithDebugError(err))
		}

		verified = ClientCertificateChainVerified(r, header)
	}

	hasNone := !hasPost && !hasBasic && assertion == nil && len(id) != 0

	return s.authenticate(ctx, id, secretBasic, secretPost, assertion, cert, verified, hasBasic, hasPost, hasNone, strategy)
}

func (s *DefaultClientAuthenticationStrategy) authenticate(ctx context.Context, id, secretBasic, secretPost string, assertion *ClientAssertion, cert *x509.Certificate, verified bool, hasBasic, hasPost, hasNone bool, strategy EndpointClientAuthStrategy) (client Client, method string, err error) {
	if assertion != nil && assertion.Client != nil {
		client = assertion.Client
	}

	if client == nil {
		if client, err = s.Store.GetClient(ctx, id); err != nil {
			return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithWrap(err).WithDebugError(err))
		}
	}

	// A certificate is an authentication method only for a client registered to use mutual TLS. For any other client
	// it is ignored here and serves only to bind tokens.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8705#section-2
	isMTLS := isMTLSAuthMethod(client, strategy)
	hasMTLS := cert != nil && isMTLS

	// A client registered to use mutual TLS never uses the 'none' method, whether or not it presented a certificate,
	// as it still sends the 'client_id' which would otherwise be read as 'none'.
	hasNone = hasNone && !isMTLS

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

	if hasMTLS {
		methods = append(methods, strategy.GetAuthMethod(client.(AuthenticationMethodClient)))
	}

	if assertion != nil {
		methods = append(methods, fmt.Sprintf("%s (i.e. %s or %s)", consts.ClientAssertionTypeJWTBearer, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodClientSecretJWT))
	}

	switch len(methods) {
	case 0:
		// The 0 case means no authentication information at all exists even if the client is a public client. This
		// likely only occurs on requests where the client_id is not known.
		return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("Client Authentication failed with no known authentication method."))
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

		return nil, "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("Client Authentication failed with more than one known authentication method included in the request which is not permitted. The registered client with id '%s' and the authorization server policy does not permit this malformed request. The `%s_endpoint_auth_method` methods determined to be used were '%s'.", client.GetID(), strategy.Name(), strings.Join(methods, "', '")))
	}

	switch {
	case hasMTLS:
		method, err = s.doAuthenticateMTLS(ctx, client, cert, verified, strategy)
	case assertion != nil:
		method, err = s.doAuthenticateAssertionJWTBearer(ctx, client, assertion, strategy)
	case hasBasic, hasPost:
		secret := secretBasic

		method = consts.ClientAuthMethodClientSecretBasic

		if hasPost && (!hasBasic || isClientSecretPostAuthMethod(client, strategy)) {
			method, secret = consts.ClientAuthMethodClientSecretPost, secretPost
		}

		err = s.doAuthenticateClientSecret(ctx, client, secret, method, strategy)
	default:
		method, err = s.doAuthenticateNone(ctx, client, strategy)
	}

	if err != nil {
		return nil, "", err
	}

	return client, method, nil
}

// NewClientAssertion converts a raw assertion string into a *ClientAssertion. A client assertion encrypted with a key
// derived from the client secret, per OpenID Connect Core 1.0 Section 10.2, is rejected, as the client it identifies
// through the 'iss' and 'sub' claims per RFC 7523 Section 3 is only known after decryption. The
// DefaultClientAuthenticationStrategy accepts such an assertion by resolving the client from the 'client_id'
// parameter first. See ClientAssertionClientSecretEncryptionDisabledProvider.
func NewClientAssertion(ctx context.Context, strategyJWT jwt.Strategy, store ClientManager, assertion, assertionType string, strategy EndpointClientAuthStrategy) (a *ClientAssertion, err error) {
	var token *jwt.Token

	switch assertionType {
	case consts.ClientAssertionTypeJWTBearer:
		if len(assertion) == 0 {
			return &ClientAssertion{Assertion: assertion, Type: assertionType}, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The request parameter 'client_assertion' must be set when using 'client_assertion_type' of '%s'.", consts.ClientAssertionTypeJWTBearer))
		}
	default:
		return &ClientAssertion{Assertion: assertion, Type: assertionType}, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("Unknown client_assertion_type '%s'.", assertionType))
	}

	if alg, ok := getClientSecretEncryptedJWTAlg(assertion); ok {
		return &ClientAssertion{Assertion: assertion, Type: assertionType}, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion was encrypted with the 'alg' header value '%s' which derives the key from the client secret, but the client cannot be identified until the client assertion is decrypted.", alg))
	}

	if token, err = strategyJWT.Decode(ctx, assertion, jwt.WithAllowUnverified(), jwt.WithSigAlgorithm(jwt.SignatureAlgorithmsNone...)); err != nil {
		return &ClientAssertion{Assertion: assertion, Type: assertionType}, resolveJWTErrorToRFCError(err)
	}

	return newClientAssertionFromToken(ctx, store, token, assertion, assertionType)
}

func (s *DefaultClientAuthenticationStrategy) newClientAssertion(ctx context.Context, id, assertion, assertionType string, strategy EndpointClientAuthStrategy) (a *ClientAssertion, err error) {
	alg, ok := getClientSecretEncryptedJWTAlg(assertion)

	if !ok || assertionType != consts.ClientAssertionTypeJWTBearer {
		return NewClientAssertion(ctx, s.Config.GetJWTStrategy(ctx), s.Store, assertion, assertionType, strategy)
	}

	a = &ClientAssertion{Assertion: assertion, Type: assertionType}

	if s.Config.GetClientAssertionClientSecretEncryptionDisabled(ctx) {
		return a, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion was encrypted with the 'alg' header value '%s' which derives the key from the client secret, but the authorization server does not permit client assertions encrypted this way.", alg))
	}

	if len(id) == 0 {
		return a, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion was encrypted with the 'alg' header value '%s' which derives the key from the client secret, but the request did not include the 'client_id' parameter which is required to identify the client before the client assertion is decrypted.", alg))
	}

	var (
		client Client
		token  *jwt.Token
	)

	if client, err = s.Store.GetClient(ctx, id); err != nil {
		return a, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithWrap(err).WithDebugf("The client with id '%s' from the 'client_id' parameter could not be found.", id))
	}

	c, ok := client.(AuthenticationMethodClient)
	if !ok {
		return a, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The registered client does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods."))
	}

	if token, err = s.Config.GetJWTStrategy(ctx).Decode(ctx, assertion, jwt.WithClient(&EndpointClientAuthJWTClient{client: c, strategy: strategy}), jwt.WithSigAlgorithm(jwt.SignatureAlgorithms...)); err != nil {
		return a, resolveJWTErrorToRFCError(err)
	}

	return newClientAssertionFromToken(ctx, s.Store, token, assertion, assertionType)
}

func newClientAssertionFromToken(ctx context.Context, store ClientManager, token *jwt.Token, assertion, assertionType string) (a *ClientAssertion, err error) {
	var (
		id, method string
		client     Client
	)

	if id, err = token.Claims.GetSubject(); err != nil || len(id) == 0 {
		if id, err = token.Claims.GetIssuer(); err != nil || len(id) == 0 {
			return &ClientAssertion{Assertion: assertion, Type: assertionType}, nil
		}
	}

	if client, err = store.GetClient(ctx, id); err != nil {
		return &ClientAssertion{Assertion: assertion, Type: assertionType, ID: id}, nil
	}

	method = consts.ClientAuthMethodPrivateKeyJWT

	if jwt.IsSignedJWTClientSecretAlg(token.SignatureAlgorithm) {
		method = consts.ClientAuthMethodClientSecretJWT
	}

	return &ClientAssertion{
		Assertion: assertion,
		Type:      assertionType,
		Parsed:    true,
		ID:        id,
		Method:    method,
		Algorithm: string(token.SignatureAlgorithm),
		Client:    client,
	}, nil
}

func getClientSecretEncryptedJWTAlg(assertion string) (alg string, ok bool) {
	if !jwt.IsEncryptedJWT(assertion) {
		return "", false
	}

	jwe, err := jose.ParseEncryptedCompact(assertion, jwt.EncryptionKeyAlgorithms, jwt.ContentEncryptionAlgorithms)
	if err != nil {
		return "", false
	}

	return jwe.Header.Algorithm, jwt.IsEncryptedJWTClientSecretAlgStr(jwe.Header.Algorithm)
}

// ClientAssertion represents a client assertion.
type ClientAssertion struct {
	Assertion, Type       string
	Parsed                bool
	ID, Method, Algorithm string
	Client                Client
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateNone(_ context.Context, client Client, strategy EndpointClientAuthStrategy) (method string, err error) {
	if c, ok := client.(AuthenticationMethodClient); ok {
		if method = strategy.GetAuthMethod(c); method != consts.ClientAuthMethodNone {
			return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s', but the method '%s' was determined to be used. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", client.GetID(), strategy.Name(), method, consts.ClientAuthMethodNone, strategy.Name(), consts.ClientAuthMethodNone, method))
		}
	}

	if !client.IsPublic() {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The '%s_endpoint_auth_method' method 'none' was determined to be used, but the registered client with id '%s' is configured with a confidential client type but only client registrations with a public client type can use this '%s_endpoint_auth_method'.", strategy.Name(), client.GetID(), strategy.Name()))
	}

	if !strategy.AllowMethodNone() {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The '%s_endpoint_auth_method' method 'none' was determined to be used, but the %s endpoint does not permit clients to authenticate using this method.", strategy.Name(), strategy.Name()))
	}

	return consts.ClientAuthMethodNone, nil
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateClientSecret(ctx context.Context, client Client, rawSecret, method string, strategy EndpointClientAuthStrategy) (err error) {
	if c, ok := client.(AuthenticationMethodClient); ok {
		switch cmethod := strategy.GetAuthMethod(c); {
		case cmethod == "" && strategy.AllowAuthMethodAny():
			break
		case cmethod != method:
			return errorsx.WithStack(
				ErrInvalidClient.
					WithHint(hintClientCredentialsInvalid).
					WithDebugf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s'. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", strategy.Name(), method, client.GetID(), strategy.Name(), cmethod, strategy.Name(), method, cmethod))
		}
	}

	switch err = CompareClientSecret(ctx, client, []byte(rawSecret)); {
	case err == nil:
		return nil
	case errors.Is(err, ErrClientSecretNotRegistered):
		return errorsx.WithStack(
			ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithDebugf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the registered client with id '%s' has no 'client_secret' which is required to process this method.", strategy.Name(), method, client.GetID()),
		)
	default:
		return errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebugError(err))
	}
}

func isClientSecretPostAuthMethod(client Client, strategy EndpointClientAuthStrategy) bool {
	c, ok := client.(AuthenticationMethodClient)

	return ok && strategy.GetAuthMethod(c) == consts.ClientAuthMethodClientSecretPost
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionJWTBearer(ctx context.Context, client Client, assertion *ClientAssertion, strategy EndpointClientAuthStrategy) (method string, err error) {
	var (
		token *jwt.Token
		c     AuthenticationMethodClient
		ok    bool
	)

	if c, ok = client.(AuthenticationMethodClient); !ok {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The registered client does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods."))
	}

	if method, _, _, token, err = s.doAuthenticateAssertionParseAssertionJWTBearer(ctx, c, assertion, strategy); err != nil {
		return "", err
	}

	if token == nil || !assertion.Parsed {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client assertion did not result in a parsed token."))
	}

	clientID := []byte(client.GetID())

	claims := &jwt.JWTClaims{}

	claims.FromMapClaims(token.Claims.ToMapClaims())

	issOK := subtle.ConstantTimeCompare([]byte(claims.Issuer), clientID) == 1
	subOK := subtle.ConstantTimeCompare([]byte(claims.Subject), clientID) == 1

	switch {
	case !issOK:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client assertion had invalid claims. Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case !subOK:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client assertion had invalid claims. Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case claims.JTI == "":
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client assertion had invalid claims. Claim 'jti' from 'client_assertion' must be set but is not."))
	default:
		switch cmethod := strategy.GetAuthMethod(c); {
		case cmethod == "" && strategy.AllowAuthMethodAny():
			break
		case cmethod != method:
			return "", errorsx.WithStack(
				ErrInvalidClient.
					WithHint(hintClientCredentialsInvalid).
					WithDebugf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s'. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", strategy.Name(), method, client.GetID(), strategy.Name(), cmethod, strategy.Name(), method, cmethod))
		}

		if !assertion.Parsed {
			return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client assertion was not able to be parsed."))
		}

		if err = s.Store.ClientAssertionJWTValid(ctx, client.GetID(), claims.JTI); err != nil {
			return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("Claim 'jti' from 'client_assertion' MUST only be used once.").WithWrap(err))
		}

		if err = s.Store.SetClientAssertionJWT(ctx, client.GetID(), claims.JTI, time.Unix(claims.ExpiresAt.Unix(), 0)); errors.Is(err, ErrJTIKnown) {
			return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("Claim 'jti' from 'client_assertion' MUST only be used once.").WithWrap(err))
		} else if err != nil {
			return "", errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
		}

		return method, nil
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearer(ctx context.Context, client AuthenticationMethodClient, assertion *ClientAssertion, strategy EndpointClientAuthStrategy) (method, kid, alg string, token *jwt.Token, err error) {
	audience := s.Config.GetAllowedJWTAssertionAudiences(ctx)

	// When enforced, the client assertion 'aud' must be solely the issuer identifier and never the token endpoint
	// URL. This differs from the authorization grant handled in handler/rfc7523, which may use either.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4
	enforceIssuerAudience := s.Config.GetEnforceClientAssertionIssuerAudience(ctx)

	if enforceIssuerAudience {
		var issuer string

		if provider, ok := s.Config.(IDTokenIssuerProvider); ok {
			issuer = provider.GetIDTokenIssuer(ctx)
		}

		if issuer == "" {
			return "", "", "", nil, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The authorization server is configured to require the issuer identifier as the sole audience of a client assertion but has no issuer identifier configured. The draft requires that an authorization server have one to be used with this specification."))
		}

		audience = []string{issuer}
	}

	if len(audience) == 0 {
		return "", "", "", nil, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The authorization server does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods as it could not determine any safe value for it's audience but it's required to validate the RFC7523 client assertions."))
	}

	// An unsigned client assertion is never acceptable, irrespective of the client's registered
	// '<endpoint>_endpoint_auth_signing_alg' value. Decode below excludes 'none' as well; this check runs first only
	// to return a diagnosable error.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
	if assertion.Algorithm == consts.JSONWebTokenAlgNone {
		return "", "", "", nil, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion for the client with id '%s' was signed with the 'alg' header value 'none' but client assertions must be signed or have a MAC applied.", client.GetID()))
	}

	if token, err = s.Config.GetJWTStrategy(ctx).Decode(ctx, assertion.Assertion, jwt.WithClient(&EndpointClientAuthJWTClient{client: client, strategy: strategy}), jwt.WithSigAlgorithm(jwt.SignatureAlgorithms...)); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, strategy, audience, err))
	}

	optsClaims := []jwt.ClaimValidationOption{
		jwt.ValidateAudienceAny(audience...), // Satisfies RFC7523 Section 3 Point 3.
		jwt.ValidateRequireExpiresAt(),       // Satisfies RFC7523 Section 3 Point 4.
		jwt.ValidateTimeFunc(time.Now),
		jwt.ValidateClockSkew(s.Config.GetJWTClockSkew(ctx)),
	}

	if err = token.Claims.Valid(optsClaims...); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, strategy, audience, err))
	}

	// Checked separately because ValidateAudienceAny is satisfied by any one entry matching, which cannot express
	// the sole value requirement.
	if enforceIssuerAudience {
		var aud jwt.ClaimStrings

		if aud, err = token.Claims.GetAudience(); err != nil {
			return "", "", "", nil, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion for the client with id '%s' had an 'aud' claim which could not be read: %s.", client.GetID(), err.Error()))
		}

		if len(aud) != 1 {
			return "", "", "", nil, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The client assertion for the client with id '%s' carries %d audience values but the issuer identifier must be its sole audience value.", client.GetID(), len(aud)))
		}
	}

	var (
		allowEmptyType bool
		types          []string
	)

	if vclient, ok := client.(ClientAssertionJWTValidationOptionsClient); ok {
		allowEmptyType = vclient.GetClientAssertionJWTValidationHeaderAllowEmptyType()
		types = vclient.GetClientAssertionJWTValidationHeaderAllowTypes()

		if len(types) == 0 {
			types = []string{jwt.JSONWebTokenTypeClientAuthentication, jwt.JSONWebTokenTypeJWT}
		}
	} else {
		allowEmptyType = true
		types = []string{jwt.JSONWebTokenTypeClientAuthentication, jwt.JSONWebTokenTypeJWT}
	}

	optsHeader := []jwt.HeaderValidationOption{
		jwt.ValidateTypes(types...),
		jwt.ValidateAllowEmptyType(allowEmptyType),
		jwt.ValidateKeyID(strategy.GetAuthSigningKeyID(client)),
		jwt.ValidateAlgorithm(strategy.GetAuthSigningAlg(client)),
		jwt.ValidateEncryptionKeyID(strategy.GetAuthEncryptionKeyID(client)),
		jwt.ValidateKeyAlgorithm(strategy.GetAuthEncryptionAlg(client)),
		jwt.ValidateContentEncryption(strategy.GetAuthEncryptionEnc(client)),
	}

	if err = token.Valid(optsHeader...); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, strategy, audience, err))
	}

	if raw, ok := token.Header[consts.JSONWebTokenHeaderKeyIdentifier]; ok {
		kid, _ = raw.(string)
	}

	if raw, ok := token.Header[consts.JSONWebTokenHeaderAlgorithm]; ok {
		alg, _ = raw.(string)
	}

	assertion.Parsed = true

	return assertion.Method, kid, alg, token, nil
}

func (s *DefaultClientAuthenticationStrategy) getClientCredentialsSecretPost(form url.Values) (id, secret string, ok bool) {
	id, secret = form.Get(consts.FormParameterClientID), form.Get(consts.FormParameterClientSecret)

	return id, secret, len(secret) != 0
}

func resolveJWTErrorToRFCError(err error) (rfc error) {
	var e *RFC6749Error

	if errors.As(err, &e) {
		return errorsx.WithStack(e)
	}

	if errJWTValidation := new(jwt.ValidationError); errors.As(err, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorMalformed):
			e = ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was malformed. %s.", strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorMalformedNotCompactSerialized):
			e = ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was malformed. The client assertion does not appear to be a JWE or JWS compact serialized JWT.")
		case errJWTValidation.Has(jwt.ValidationErrorUnverifiable):
			e = ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was not able to be verified. %s.", strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		default:
			e = ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithWrap(err).
				WithDebugf("Unknown error occurred handling the client assertion.")
		}
	}

	return errorsx.WithStack(e)
}

//nolint:gocyclo
func fmtClientAssertionDecodeError(token *jwt.Token, client AuthenticationMethodClient, strategy EndpointClientAuthStrategy, audience []string, inner error) (outer *RFC6749Error) {
	outer = ErrInvalidClient.WithWrap(inner).WithHint(hintClientCredentialsInvalid)

	if token == nil {
		token = &jwt.Token{Claims: jwt.MapClaims{}}
	}

	if errJWTValidation := new(jwt.ValidationError); errors.As(inner, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyIDInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'kid' header value '%s' due to the client registration 'request_object_signing_key_id' value but the client assertion was signed with the 'kid' header value '%s'.", client.GetID(), strategy.GetAuthSigningKeyID(client), token.KeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderAlgorithmInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'alg' header value '%s' due to the client registration 'request_object_signing_alg' value but the client assertion was signed with the 'alg' header value '%s'.", client.GetID(), strategy.GetAuthSigningAlg(client), token.SignatureAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'typ' header value '%s' or '%s' but the client assertion was signed with the 'typ' header value '%s'.", client.GetID(), jwt.JSONWebTokenTypeClientAuthentication, jwt.JSONWebTokenTypeJWT, fmtHeaderValue(token.Header, jwt.JSONWebTokenHeaderType))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'typ' header value '%s' but the client assertion was encrypted with the 'typ' header value '%s'.", client.GetID(), jwt.JSONWebTokenTypeJWT, fmtHeaderValue(token.HeaderJWE, jwt.JSONWebTokenHeaderType))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'cty' header value '%s' but the client assertion was encrypted with the 'cty' header value '%s'.", client.GetID(), jwt.JSONWebTokenTypeJWT, fmtHeaderValue(token.HeaderJWE, jwt.JSONWebTokenHeaderContentType))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionKeyIDInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'kid' header value '%s' due to the client registration 'request_object_encryption_key_id' value but the client assertion was encrypted with the 'kid' header value '%s'.", client.GetID(), strategy.GetAuthEncryptionKeyID(client), token.EncryptionKeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyAlgorithmInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'alg' header value '%s' due to the client registration 'request_object_encryption_alg' value but the client assertion was encrypted with the 'alg' header value '%s'.", client.GetID(), strategy.GetAuthEncryptionAlg(client), token.KeyAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentEncryptionInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'enc' header value '%s' due to the client registration 'request_object_encryption_enc' value but the client assertion was encrypted with the 'enc' header value '%s'.", client.GetID(), strategy.GetAuthEncryptionEnc(client), token.ContentEncryption)
		case errJWTValidation.Has(jwt.ValidationErrorMalformedNotCompactSerialized):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was malformed. The client assertion does not appear to be a JWE or JWS compact serialized JWT.", client.GetID())
		case errJWTValidation.Has(jwt.ValidationErrorMalformed):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was malformed. %s.", client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorUnverifiable):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was not able to be verified. %s.", client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorSignatureInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that has an invalid signature. %s.", client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorExpired):
			exp, err := token.Claims.GetExpirationTime()
			if err == nil && exp != nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was expired. The client assertion expired at %d.", client.GetID(), exp.Int64())
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was expired. The client assertion does not have an 'exp' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuedAt):
			iat, err := token.Claims.GetIssuedAt()
			if err == nil && iat != nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion was issued at %d.", client.GetID(), iat.Int64())
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion does not have an 'iat' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorNotValidYet):
			nbf, err := token.Claims.GetNotBefore()
			if err == nil && nbf != nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion is not valid before %d.", client.GetID(), nbf.Int64())
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion does not have an 'nbf' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuer):
			iss, err := token.Claims.GetIssuer()
			if err == nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that has an invalid issuer. The client assertion was expected to have an 'iss' claim which matches the value '%s' but the 'iss' claim had the value '%s'.", client.GetID(), client.GetID(), iss)
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that has an invalid issuer. The client assertion does not have an 'iss' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorAudience):
			aud, err := token.Claims.GetAudience()
			if err == nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that has an invalid audience. The client assertion was expected to have an 'aud' claim which matches one of the values '%s' but the 'aud' claim had the values '%s'.", client.GetID(), strings.Join(audience, "', '"), strings.Join(aud, "', '"))
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that has an invalid audience. The client assertion does not have an 'aud' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorClaimsInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that had one or more invalid claims. Error occurred trying to validate the client assertions claims: %s", client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		default:
			return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that could not be validated. Error occurred trying to validate the client assertion: %s", client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		}
	} else if errJWKLookup := new(jwt.JWKLookupError); errors.As(inner, &errJWKLookup) {
		return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that could not be validated due to a key lookup error. %s.", client.GetID(), errJWKLookup.Description)
	} else {
		return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that could not be validated. %s.", client.GetID(), ErrorToDebugRFC6749Error(inner).Error())
	}
}

func fmtHeaderValue(header map[string]any, key string) string {
	switch v := header[key].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
