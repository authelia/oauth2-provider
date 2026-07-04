// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientAuthenticationStrategy describes a client authentication strategy implementation.
type ClientAuthenticationStrategy interface {
	AuthenticateClient(ctx context.Context, r *http.Request, form url.Values, strategy EndpointClientAuthStrategy) (client Client, method string, err error)
}

var (
	ErrClientSecretNotRegistered = errors.New("error occurred checking the client secret: the client is not registered with a secret")
)

// AuthenticateClient authenticates client requests using the configured strategy returned by the oauth2.Configurator
// function GetClientAuthenticationStrategy, if nil it uses `oauth2.DefaultClientAuthenticationStrategy`.
func (f *Fosite) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (client Client, method string, err error) {
	return f.AuthenticateClientWithAuthHandler(ctx, r, form, f.Config.GetTokenEndpointClientAuthStrategy(ctx))
}

// AuthenticateClientWithAuthHandler authenticates a client at the endpoint represented by handler using the configured
// ClientAuthenticationStrategy, falling back to DefaultClientAuthenticationStrategy if none is configured. Use this in
// preference to AuthenticateClient when the request is not destined for the token endpoint.
func (f *Fosite) AuthenticateClientWithAuthHandler(ctx context.Context, r *http.Request, form url.Values, strategyECA EndpointClientAuthStrategy) (client Client, method string, err error) {
	var strategy ClientAuthenticationStrategy

	if strategy = f.Config.GetClientAuthenticationStrategy(ctx); strategy == nil {
		strategy = &DefaultClientAuthenticationStrategy{Store: f.Store, Config: f.Config}
	}

	return strategy.AuthenticateClient(ctx, r, form, strategyECA)
}

// CompareClientSecret compares a raw secret input from a client to the registered client secret. If the secret is valid
// it returns nil, otherwise it returns an error. The ErrClientSecretNotRegistered error indicates the ClientSecret
// is nil, all other errors are returned directly from the ClientSecret.Compare function.
func CompareClientSecret(ctx context.Context, client Client, rawSecret []byte) (err error) {
	secret := client.GetClientSecret()

	if secret == nil || !secret.Valid() {
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

func getClientCredentialsSecretBasic(r *http.Request) (id, secret string, ok bool, err error) {
	auth := r.Header.Get(consts.HeaderAuthorization)

	if auth == "" {
		return "", "", false, nil
	}

	scheme, value, ok := strings.Cut(auth, " ")

	if !ok {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithWrap(err).WithDebug("The header value is either missing a scheme, value, or the separator between them."))
	}

	if !strings.EqualFold(scheme, "Basic") {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebugf("The scheme '%s' is not known for client authentication.", scheme))
	}

	c, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithWrap(err).WithDebugf("Error occurred performing a base64 decode: %+v.", err))
	}

	cs := string(c)

	id, secret, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The basic scheme value was not separated by a colon."))
	}

	if id, err = url.QueryUnescape(id); err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client id in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err))
	}

	if secret, err = url.QueryUnescape(secret); err != nil {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client secret in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err))
	}

	if len(id) != 0 && !RegexSpecificationVSCHAR.MatchString(id) {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client id in the HTTP request had an invalid character."))
	}

	if len(secret) != 0 && !RegexSpecificationVSCHAR.MatchString(secret) {
		return "", "", false, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client secret in the HTTP request had an invalid character."))
	}

	return id, secret, secret != "", nil
}

func getClientCredentialsClientAssertion(form url.Values) (assertion, assertionType string, hasAssertion bool) {
	assertionType, assertion = form.Get(consts.FormParameterClientAssertionType), form.Get(consts.FormParameterClientAssertion)

	return assertion, assertionType, len(assertion) != 0 || len(assertionType) != 0
}

func getClientCredentialsClientIDValid(post, header string, assertion *ClientAssertion) (id string, err error) {
	if len(post) != 0 && len(header) != 0 && post != header {
		return "", errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The HTTP Basic Authorization header specified the 'client_id' value '%s' but the request body specified the 'client_id' value '%s'. Per RFC 6749 Section 2.3 a client MUST NOT use more than one authentication method.", header, post))
	}

	if len(post) != 0 {
		id = post
	} else if len(header) != 0 {
		id = header
	}

	if len(id) == 0 {
		if assertion != nil {
			return assertion.ID, nil
		}

		return id, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The Client ID was missing from the request but it is required when there is no client assertion."))
	}

	if !RegexSpecificationVSCHAR.MatchString(id) {
		return id, errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The client id in the request had an invalid character."))
	}

	return id, nil
}

// EndpointClientAuthStrategy abstracts the per-endpoint client authentication configuration so that a single
// ClientAuthenticationStrategy implementation can authenticate clients across the various endpoints that support client
// authentication (i.e. the token, introspection, and revocation endpoints). Each endpoint reads different client
// metadata (for example the 'token_endpoint_auth_method' versus the 'introspection_endpoint_auth_method') and enforces
// a different policy, and this strategy resolves the correct values and policy for the endpoint it represents.
type EndpointClientAuthStrategy interface {
	// GetAuthMethod returns the registered client authentication method configured for this endpoint (for example the
	// value of the client's 'token_endpoint_auth_method').
	GetAuthMethod(client AuthenticationMethodClient) string

	// GetAuthSigningKeyID returns the registered signing key id used to verify client assertions at this endpoint.
	GetAuthSigningKeyID(client AuthenticationMethodClient) string

	// GetAuthSigningAlg returns the registered signing algorithm used to verify client assertions at this endpoint.
	GetAuthSigningAlg(client AuthenticationMethodClient) string

	// GetAuthEncryptionKeyID returns the registered encryption key id used for client assertions at this endpoint.
	GetAuthEncryptionKeyID(client AuthenticationMethodClient) string

	// GetAuthEncryptionAlg returns the registered encryption key algorithm used for client assertions at this endpoint.
	GetAuthEncryptionAlg(client AuthenticationMethodClient) string

	// GetAuthEncryptionEnc returns the registered content encryption algorithm used for client assertions at this
	// endpoint.
	GetAuthEncryptionEnc(client AuthenticationMethodClient) string

	// Name returns the name of the endpoint this strategy represents, used when building error and log messages (for
	// example 'token', 'introspection', or 'revocation').
	Name() string

	// AllowAuthMethodAny returns true if this endpoint permits any client authentication method when the client has not
	// registered a specific method for the endpoint.
	AllowAuthMethodAny() bool

	// AllowMethodNone returns true if this endpoint permits clients to authenticate using the 'none' method.
	// When false, a client using the 'none' method is rejected even if it is otherwise correctly configured.
	AllowMethodNone() bool
}

// EndpointClientAuthJWTClient adapts an AuthenticationMethodClient and its EndpointClientAuthStrategy into a jwt.Client.
// It is passed to the jwt.Strategy when decoding a client assertion (i.e. the 'private_key_jwt' or 'client_secret_jwt'
// method) so the assertion is verified using the keys and algorithms configured for the endpoint the strategy
// represents.
type EndpointClientAuthJWTClient struct {
	client   AuthenticationMethodClient
	strategy EndpointClientAuthStrategy
}

// GetID returns the underlying client's ID.
func (c *EndpointClientAuthJWTClient) GetID() string {
	return c.client.GetID()
}

// GetClientSecretPlainText returns the underlying client's plaintext secret, used to verify 'client_secret_jwt'
// assertions. See jwt.BaseClient for the semantics of the return values.
func (c *EndpointClientAuthJWTClient) GetClientSecretPlainText() (secret []byte, ok bool, err error) {
	return c.client.GetClientSecretPlainText()
}

// GetJSONWebKeys returns the underlying client's registered JSON Web Key Set used to verify 'private_key_jwt'
// assertions.
func (c *EndpointClientAuthJWTClient) GetJSONWebKeys() (jwks *jose.JSONWebKeySet) {
	return c.client.GetJSONWebKeys()
}

// GetJSONWebKeysURI returns the underlying client's registered JSON Web Key Set URI used to verify 'private_key_jwt'
// assertions.
func (c *EndpointClientAuthJWTClient) GetJSONWebKeysURI() (uri string) {
	return c.client.GetJSONWebKeysURI()
}

// GetSigningKeyID returns an empty key id as the key is resolved from the client's JSON Web Key Set rather than a fixed
// key id.
func (c *EndpointClientAuthJWTClient) GetSigningKeyID() (kid string) {
	return ""
}

// GetSigningAlg returns the signing algorithm configured for the endpoint, resolved via the strategy (for example the
// client's 'token_endpoint_auth_signing_alg').
func (c *EndpointClientAuthJWTClient) GetSigningAlg() (alg string) {
	return c.strategy.GetAuthSigningAlg(c.client)
}

// GetEncryptionKeyID returns an empty key id as client assertions are verified, not encrypted, by this client.
func (c *EndpointClientAuthJWTClient) GetEncryptionKeyID() (kid string) {
	return ""
}

// GetEncryptionAlg returns an empty algorithm as client assertions are verified, not encrypted, by this client.
func (c *EndpointClientAuthJWTClient) GetEncryptionAlg() (alg string) {
	return ""
}

// GetEncryptionEnc returns an empty content encryption algorithm as client assertions are verified, not encrypted, by
// this client.
func (c *EndpointClientAuthJWTClient) GetEncryptionEnc() (enc string) {
	return ""
}

// IsClientSigned returns true as a client assertion is always signed by the client.
func (c *EndpointClientAuthJWTClient) IsClientSigned() (is bool) {
	return true
}

// TokenEndpointClientAuthStrategy is the EndpointClientAuthStrategy for the token endpoint. It resolves client
// authentication configuration from the client's 'token_endpoint_auth_method' metadata and permits public clients to
// authenticate using the 'none' method.
type TokenEndpointClientAuthStrategy struct{}

// GetAuthMethod returns the client's registered 'token_endpoint_auth_method'.
func (s *TokenEndpointClientAuthStrategy) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetTokenEndpointAuthMethod()
}

// GetAuthSigningKeyID returns the signing key id used to verify client assertions at the token endpoint.
func (s *TokenEndpointClientAuthStrategy) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthSigningAlg returns the client's registered 'token_endpoint_auth_signing_alg'.
func (s *TokenEndpointClientAuthStrategy) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetTokenEndpointAuthSigningAlg()
}

// GetAuthEncryptionKeyID returns the encryption key id used for client assertions at the token endpoint.
func (s *TokenEndpointClientAuthStrategy) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionAlg returns the encryption key algorithm used for client assertions at the token endpoint.
func (s *TokenEndpointClientAuthStrategy) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionEnc returns the content encryption algorithm used for client assertions at the token endpoint.
func (s *TokenEndpointClientAuthStrategy) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

// Name returns 'token', the name of the endpoint this strategy represents.
func (s *TokenEndpointClientAuthStrategy) Name() string {
	return "token"
}

// AllowAuthMethodAny returns false as the token endpoint requires a client to use its registered authentication method.
func (s *TokenEndpointClientAuthStrategy) AllowAuthMethodAny() bool {
	return false
}

// AllowPublicClients returns true as the token endpoint permits public clients to authenticate using the 'none' method.
func (s *TokenEndpointClientAuthStrategy) AllowMethodNone() bool {
	return true
}

// IntrospectionEndpointClientAuthStrategy is the EndpointClientAuthStrategy for the introspection endpoint. It resolves
// client authentication configuration from the client's 'introspection_endpoint_auth_method' metadata and does not
// permit public clients to authenticate using the 'none' method.
type IntrospectionEndpointClientAuthStrategy struct{}

// GetAuthMethod returns the client's registered 'introspection_endpoint_auth_method'.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetIntrospectionEndpointAuthMethod()
}

// GetAuthSigningKeyID returns the signing key id used to verify client assertions at the introspection endpoint.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthSigningAlg returns the client's registered 'introspection_endpoint_auth_signing_alg'.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetIntrospectionEndpointAuthSigningAlg()
}

// GetAuthEncryptionKeyID returns the encryption key id used for client assertions at the introspection endpoint.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionAlg returns the encryption key algorithm used for client assertions at the introspection endpoint.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionEnc returns the content encryption algorithm used for client assertions at the introspection
// endpoint.
func (s *IntrospectionEndpointClientAuthStrategy) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

// Name returns 'introspection', the name of the endpoint this strategy represents.
func (s *IntrospectionEndpointClientAuthStrategy) Name() string {
	return "introspection"
}

// AllowAuthMethodAny returns true as the introspection endpoint permits any authentication method when the client has
// not registered a specific 'introspection_endpoint_auth_method'.
func (s *IntrospectionEndpointClientAuthStrategy) AllowAuthMethodAny() bool {
	return true
}

// AllowPublicClients returns false as the introspection endpoint does not permit public clients to authenticate using
// the 'none' method.
func (s *IntrospectionEndpointClientAuthStrategy) AllowMethodNone() bool {
	return false
}

// RevocationEndpointClientAuthStrategy is the EndpointClientAuthStrategy for the revocation endpoint. It resolves client
// authentication configuration from the client's 'revocation_endpoint_auth_method' metadata and permits public clients
// to authenticate using the 'none' method.
type RevocationEndpointClientAuthStrategy struct{}

// GetAuthMethod returns the client's registered 'revocation_endpoint_auth_method'.
func (s *RevocationEndpointClientAuthStrategy) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetRevocationEndpointAuthMethod()
}

// GetAuthSigningKeyID returns the signing key id used to verify client assertions at the revocation endpoint.
func (s *RevocationEndpointClientAuthStrategy) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthSigningAlg returns the client's registered 'revocation_endpoint_auth_signing_alg'.
func (s *RevocationEndpointClientAuthStrategy) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetRevocationEndpointAuthSigningAlg()
}

// GetAuthEncryptionKeyID returns the encryption key id used for client assertions at the revocation endpoint.
func (s *RevocationEndpointClientAuthStrategy) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionAlg returns the encryption key algorithm used for client assertions at the revocation endpoint.
func (s *RevocationEndpointClientAuthStrategy) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

// GetAuthEncryptionEnc returns the content encryption algorithm used for client assertions at the revocation endpoint.
func (s *RevocationEndpointClientAuthStrategy) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

// Name returns 'revocation', the name of the endpoint this strategy represents.
func (s *RevocationEndpointClientAuthStrategy) Name() string {
	return "revocation"
}

// AllowAuthMethodAny returns true as the revocation endpoint permits any authentication method when the client has not
// registered a specific 'revocation_endpoint_auth_method'.
func (s *RevocationEndpointClientAuthStrategy) AllowAuthMethodAny() bool {
	return true
}

// AllowPublicClients returns true as the revocation endpoint permits public clients to authenticate using the 'none'
// method.
func (s *RevocationEndpointClientAuthStrategy) AllowMethodNone() bool {
	return true
}

// PrivateKey properly describes crypto.PrivateKey.
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}
