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
	}
}

func (s *DefaultClientAuthenticationStrategy) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values, handler EndpointClientAuthHandler) (client Client, method string, err error) {
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
		if assertion, err = NewClientAssertion(ctx, s.Config.GetJWTStrategy(ctx), s.Store, assertionValue, assertionType, handler); err != nil {
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

	return s.authenticate(ctx, id, secret, assertion, hasBasic, hasPost, hasNone, handler)
}

func (s *DefaultClientAuthenticationStrategy) authenticate(ctx context.Context, id, secret string, assertion *ClientAssertion, hasBasic, hasPost, hasNone bool, handler EndpointClientAuthHandler) (client Client, method string, err error) {
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
			WithDebugf("The registered client with id '%s' and the authorization server policy does not permit this malformed request. The `%s_endpoint_auth_method` methods determined to be used were '%s'.", client.GetID(), handler.Name(), strings.Join(methods, "', '")))
	}

	switch {
	case assertion != nil:
		method, err = s.doAuthenticateAssertionJWTBearer(ctx, client, assertion, handler)
	case hasBasic, hasPost:
		method, err = s.doAuthenticateClientSecret(ctx, client, secret, hasBasic, hasPost, handler)
	default:
		method, err = s.doAuthenticateNone(ctx, client, handler)
	}

	if err != nil {
		return nil, "", err
	}

	return client, method, nil
}

// NewClientAssertion converts a raw assertion string into a *ClientAssertion.
func NewClientAssertion(ctx context.Context, strategy jwt.Strategy, store ClientManager, assertion, assertionType string, handler EndpointClientAuthHandler) (a *ClientAssertion, err error) {
	var (
		token *jwt.Token

		id, method string
		client     Client
	)

	switch assertionType {
	case consts.ClientAssertionTypeJWTBearer:
		if len(assertion) == 0 {
			return &ClientAssertion{Assertion: assertion, Type: assertionType}, errorsx.WithStack(ErrInvalidRequest.WithHintf("The request parameter 'client_assertion' must be set when using 'client_assertion_type' of '%s'.", consts.ClientAssertionTypeJWTBearer))
		}
	default:
		return &ClientAssertion{Assertion: assertion, Type: assertionType}, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unknown client_assertion_type '%s'.", assertionType))
	}

	if token, err = strategy.Decode(ctx, assertion, jwt.WithAllowUnverified(), jwt.WithSigAlgorithm(jwt.SignatureAlgorithmsNone...)); err != nil {
		return &ClientAssertion{Assertion: assertion, Type: assertionType}, resolveJWTErrorToRFCError(err)
	}

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

// ClientAssertion represents a client assertion.
type ClientAssertion struct {
	Assertion, Type       string
	Parsed                bool
	ID, Method, Algorithm string
	Client                Client
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateNone(_ context.Context, client Client, handler EndpointClientAuthHandler) (method string, err error) {
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

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionJWTBearer(ctx context.Context, client Client, assertion *ClientAssertion, handler EndpointClientAuthHandler) (method string, err error) {
	var (
		token *jwt.Token
		c     AuthenticationMethodClient
		ok    bool
	)

	if c, ok = client.(AuthenticationMethodClient); !ok {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The registered client does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods."))
	}

	if method, _, _, token, err = s.doAuthenticateAssertionParseAssertionJWTBearer(ctx, c, assertion, handler); err != nil {
		return "", err
	}

	if token == nil || !assertion.Parsed {
		return "", errorsx.WithStack(ErrInvalidClient.WithDebug("The client assertion did not result in a parsed token."))
	}

	clientID := []byte(client.GetID())

	claims := &jwt.JWTClaims{}

	claims.FromMapClaims(token.Claims.ToMapClaims())

	switch {
	case subtle.ConstantTimeCompare([]byte(claims.Issuer), clientID) == 0:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("The client assertion had invalid claims.").WithDebug("Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case subtle.ConstantTimeCompare([]byte(claims.Subject), clientID) == 0:
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("The client assertion had invalid claims.").WithDebug("Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
	case claims.JTI == "":
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("The client assertion had invalid claims.").WithDebug("Claim 'jti' from 'client_assertion' must be set but is not."))
	default:
		switch cmethod := handler.GetAuthMethod(c); {
		case cmethod == "" && handler.AllowAuthMethodAny():
			break
		case cmethod != method:
			return "", errorsx.WithStack(
				ErrInvalidClient.
					WithHintf("The request was determined to be using '%s_endpoint_auth_method' method '%s', however the OAuth 2.0 client registration does not allow this method.", handler.Name(), method).
					WithDebugf("The registered client with id '%s' is configured to only support '%s_endpoint_auth_method' method '%s'. Either the Authorization Server client registration will need to have the '%s_endpoint_auth_method' updated to '%s' or the Relying Party will need to be configured to use '%s'.", client.GetID(), handler.Name(), cmethod, handler.Name(), method, cmethod))
		}

		if !assertion.Parsed {
			return "", errorsx.WithStack(ErrInvalidClient.WithDebug("The client assertion was not able to be parsed."))
		}

		if err = s.Store.ClientAssertionJWTValid(ctx, claims.JTI); err != nil {
			return "", errorsx.WithStack(ErrJTIKnown.WithHint("Claim 'jti' from 'client_assertion' MUST only be used once.").WithDebugError(err))
		}

		if err = s.Store.SetClientAssertionJWT(ctx, claims.JTI, time.Unix(claims.ExpiresAt.Unix(), 0)); err != nil {
			return "", err
		}

		return method, nil
	}
}

func (s *DefaultClientAuthenticationStrategy) doAuthenticateAssertionParseAssertionJWTBearer(ctx context.Context, client AuthenticationMethodClient, assertion *ClientAssertion, handler EndpointClientAuthHandler) (method, kid, alg string, token *jwt.Token, err error) {
	audience := s.Config.GetAllowedJWTAssertionAudiences(ctx)

	if len(audience) == 0 {
		return "", "", "", nil, errorsx.WithStack(ErrMisconfiguration.WithHint("The authorization server does not support OAuth 2.0 JWT Profile Client Authentication RFC7523 or OpenID Connect 1.0 specific authentication methods.").WithDebug("The authorization server could not determine any safe value for it's audience but it's required to validate the RFC7523 client assertions."))
	}

	if token, err = s.Config.GetJWTStrategy(ctx).Decode(ctx, assertion.Assertion, jwt.WithClient(&EndpointClientAuthJWTClient{client: client, handler: handler}), jwt.WithSigAlgorithm(jwt.SignatureAlgorithmsNone...)); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, handler, audience, err))
	}

	optsClaims := []jwt.ClaimValidationOption{
		jwt.ValidateAudienceAny(audience...), // Satisfies RFC7523 Section 3 Point 3.
		jwt.ValidateRequireExpiresAt(),       // Satisfies RFC7523 Section 3 Point 4.
		jwt.ValidateTimeFunc(time.Now),
	}

	if err = token.Claims.Valid(optsClaims...); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, handler, audience, err))
	}

	optsHeader := []jwt.HeaderValidationOption{
		jwt.ValidateKeyID(handler.GetAuthSigningKeyID(client)),
		jwt.ValidateAlgorithm(handler.GetAuthSigningAlg(client)),
		jwt.ValidateEncryptionKeyID(handler.GetAuthEncryptionKeyID(client)),
		jwt.ValidateKeyAlgorithm(handler.GetAuthEncryptionAlg(client)),
		jwt.ValidateContentEncryption(handler.GetAuthEncryptionEnc(client)),
	}

	if err = token.Valid(optsHeader...); err != nil {
		return "", "", "", nil, errorsx.WithStack(fmtClientAssertionDecodeError(token, client, handler, audience, err))
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

	return id, secret, len(id) != 0 && len(secret) != 0
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
				WithHint("OAuth 2.0 client provided a client assertion which could not be decoded or validated.").
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was malformed. %s.", strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorMalformedNotCompactSerialized):
			e = ErrInvalidClient.
				WithHint("OAuth 2.0 client provided a client assertion which could not be decoded or validated.").
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was malformed. The client assertion does not appear to be a JWE or JWS compact serialized JWT.")
		case errJWTValidation.Has(jwt.ValidationErrorUnverifiable):
			e = ErrInvalidClient.
				WithHint("OAuth 2.0 client provided a client assertion which could not be decoded or validated.").
				WithWrap(err).
				WithDebugf("OAuth 2.0 client provided a client assertion that was not able to be verified. %s.", strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		default:
			e = ErrInvalidClient.
				WithHint("OAuth 2.0 client provided a client assertion which could not be decoded or validated.").
				WithWrap(err).
				WithDebugf("Unknown error occurred handling the client assertion.")
		}
	}

	return errorsx.WithStack(e)
}

//nolint:gocyclo
func fmtClientAssertionDecodeError(token *jwt.Token, client AuthenticationMethodClient, handler EndpointClientAuthHandler, audience []string, inner error) (outer *RFC6749Error) {
	outer = ErrInvalidClient.WithWrap(inner).WithHintf("OAuth 2.0 client with id '%s' provided a client assertion which could not be decoded or validated.", client.GetID())

	if errJWTValidation := new(jwt.ValidationError); errors.As(inner, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyIDInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'kid' header value '%s' due to the client registration 'request_object_signing_key_id' value but the client assertion was signed with the 'kid' header value '%s'.", client.GetID(), handler.GetAuthSigningKeyID(client), token.KeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderAlgorithmInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'alg' header value '%s' due to the client registration 'request_object_signing_alg' value but the client assertion was signed with the 'alg' header value '%s'.", client.GetID(), handler.GetAuthSigningAlg(client), token.SignatureAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be signed with the 'typ' header value '%s' but the client assertion was signed with the 'typ' header value '%s'.", client.GetID(), consts.JSONWebTokenTypeJWT, token.Header[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'typ' header value '%s' but the client assertion was encrypted with the 'typ' header value '%s'.", client.GetID(), consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalidMismatch):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with a 'cty' header value and signed with a 'typ' value that match but the client assertions was encrypted with the 'cty' header value '%s' and signed with the 'typ' header value '%s'.", client.GetID(), token.HeaderJWE[consts.JSONWebTokenHeaderContentType], token.HeaderJWE[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'cty' header value '%s' but the client assertion was encrypted with the 'cty' header value '%s'.", client.GetID(), consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderContentType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionKeyIDInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'kid' header value '%s' due to the client registration 'request_object_encryption_key_id' value but the client assertion was encrypted with the 'kid' header value '%s'.", client.GetID(), handler.GetAuthEncryptionKeyID(client), token.EncryptionKeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyAlgorithmInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'alg' header value '%s' due to the client registration 'request_object_encryption_alg' value but the client assertion was encrypted with the 'alg' header value '%s'.", client.GetID(), handler.GetAuthEncryptionAlg(client), token.KeyAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentEncryptionInvalid):
			return outer.WithDebugf("OAuth 2.0 client with id '%s' expects client assertions to be encrypted with the 'enc' header value '%s' due to the client registration 'request_object_encryption_enc' value but the client assertion was encrypted with the 'enc' header value '%s'.", client.GetID(), handler.GetAuthEncryptionEnc(client), token.ContentEncryption)
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
			if err == nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was expired. The client assertion expired at %d.", client.GetID(), exp.Int64())
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was expired. The client assertion does not have an 'exp' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuedAt):
			iat, err := token.Claims.GetIssuedAt()
			if err == nil {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion was issued at %d.", client.GetID(), iat.Int64())
			} else {
				return outer.WithDebugf("OAuth 2.0 client with id '%s' provided a client assertion that was issued in the future. The client assertion does not have an 'iat' claim or it has an invalid type.", client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorNotValidYet):
			nbf, err := token.Claims.GetNotBefore()
			if err == nil {
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
