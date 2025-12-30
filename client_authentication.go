// Copyright © 2023 Ory Corp
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
	AuthenticateClient(ctx context.Context, r *http.Request, form url.Values, handler EndpointClientAuthHandler) (client Client, method string, err error)
}

var (
	ErrClientSecretNotRegistered = errors.New("error occurred checking the client secret: the client is not registered with a secret")
)

// AuthenticateClient authenticates client requests using the configured strategy returned by the oauth2.Configurator
// function GetClientAuthenticationStrategy, if nil it uses `oauth2.DefaultClientAuthenticationStrategy`.
func (f *Fosite) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (client Client, method string, err error) {
	return f.AuthenticateClientWithAuthHandler(ctx, r, form, &TokenEndpointClientAuthHandler{})
}

func (f *Fosite) AuthenticateClientWithAuthHandler(ctx context.Context, r *http.Request, form url.Values, handler EndpointClientAuthHandler) (client Client, method string, err error) {
	var strategy ClientAuthenticationStrategy

	if strategy = f.Config.GetClientAuthenticationStrategy(ctx); strategy == nil {
		strategy = &DefaultClientAuthenticationStrategy{Store: f.Store, Config: f.Config}
	}

	return strategy.AuthenticateClient(ctx, r, form, handler)
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

func getClientCredentialsClientAssertion(form url.Values) (assertion, assertionType string, hasAssertion bool) {
	assertionType, assertion = form.Get(consts.FormParameterClientAssertionType), form.Get(consts.FormParameterClientAssertion)

	return assertion, assertionType, len(assertion) != 0 || len(assertionType) != 0
}

func getClientCredentialsClientIDValid(post, header string, assertion *ClientAssertion) (id string, err error) {
	if len(post) != 0 {
		id = post
	} else if len(header) != 0 {
		id = header
	}

	if len(id) == 0 {
		if assertion != nil {
			return assertion.ID, nil
		}

		return id, errorsx.WithStack(ErrInvalidRequest.WithHint("Client Credentials missing or malformed.").WithDebug("The Client ID was missing from the request but it is required when there is no client assertion."))
	}

	if !RegexSpecificationVSCHAR.MatchString(id) {
		return id, errorsx.WithStack(ErrInvalidRequest.WithHint("The client id in the request had an invalid character."))
	}

	return id, nil
}

// EndpointClientAuthHandler is a helper implementation to assist with producing the correct values while using multiple
// endpoint implementations.
type EndpointClientAuthHandler interface {
	// GetAuthMethod returns the appropriate auth method for this client.
	GetAuthMethod(client AuthenticationMethodClient) string

	// GetAuthSigningKeyID returns the appropriate auth signature key id for this client.
	GetAuthSigningKeyID(client AuthenticationMethodClient) string

	// GetAuthSigningAlg returns the appropriate auth signature algorithm for this client.
	GetAuthSigningAlg(client AuthenticationMethodClient) string

	// GetAuthEncryptionKeyID returns the appropriate auth encryption key id for this client.
	GetAuthEncryptionKeyID(client AuthenticationMethodClient) string

	// GetAuthEncryptionAlg returns the appropriate auth encryption key algorithm for this client.
	GetAuthEncryptionAlg(client AuthenticationMethodClient) string

	// GetAuthEncryptionEnc returns the appropriate auth encryption content encryption for this client.
	GetAuthEncryptionEnc(client AuthenticationMethodClient) string

	// Name returns the appropriate name for this endpoint for logging purposes.
	Name() string

	// AllowAuthMethodAny returns true if this endpoint client auth handler is allowed to be used for any method if not configured.
	AllowAuthMethodAny() bool
}

type EndpointClientAuthJWTClient struct {
	client  AuthenticationMethodClient
	handler EndpointClientAuthHandler
}

func (c *EndpointClientAuthJWTClient) GetID() string {
	return c.client.GetID()
}

func (c *EndpointClientAuthJWTClient) GetClientSecretPlainText() (secret []byte, ok bool, err error) {
	return c.client.GetClientSecretPlainText()
}

func (c *EndpointClientAuthJWTClient) GetJSONWebKeys() (jwks *jose.JSONWebKeySet) {
	return c.client.GetJSONWebKeys()
}

func (c *EndpointClientAuthJWTClient) GetJSONWebKeysURI() (uri string) {
	return c.client.GetJSONWebKeysURI()
}

func (c *EndpointClientAuthJWTClient) GetSigningKeyID() (kid string) {
	return ""
}

func (c *EndpointClientAuthJWTClient) GetSigningAlg() (alg string) {
	return c.handler.GetAuthSigningAlg(c.client)
}

func (c *EndpointClientAuthJWTClient) GetEncryptionKeyID() (kid string) {
	return ""
}

func (c *EndpointClientAuthJWTClient) GetEncryptionAlg() (alg string) {
	return ""
}

func (c *EndpointClientAuthJWTClient) GetEncryptionEnc() (enc string) {
	return ""
}

func (c *EndpointClientAuthJWTClient) IsClientSigned() (is bool) {
	return true
}

type TokenEndpointClientAuthHandler struct{}

func (h *TokenEndpointClientAuthHandler) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetTokenEndpointAuthMethod()
}

func (h *TokenEndpointClientAuthHandler) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *TokenEndpointClientAuthHandler) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetTokenEndpointAuthSigningAlg()
}

func (h *TokenEndpointClientAuthHandler) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *TokenEndpointClientAuthHandler) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

func (h *TokenEndpointClientAuthHandler) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

func (h *TokenEndpointClientAuthHandler) Name() string {
	return "token"
}

func (h *TokenEndpointClientAuthHandler) AllowAuthMethodAny() bool {
	return false
}

type IntrospectionEndpointClientAuthHandler struct{}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetIntrospectionEndpointAuthMethod()
}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetIntrospectionEndpointAuthSigningAlg()
}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

func (h *IntrospectionEndpointClientAuthHandler) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

func (h *IntrospectionEndpointClientAuthHandler) Name() string {
	return "introspection"
}

func (h *IntrospectionEndpointClientAuthHandler) AllowAuthMethodAny() bool {
	return true
}

type RevocationEndpointClientAuthHandler struct{}

func (h *RevocationEndpointClientAuthHandler) GetAuthMethod(client AuthenticationMethodClient) string {
	return client.GetRevocationEndpointAuthMethod()
}

func (h *RevocationEndpointClientAuthHandler) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *RevocationEndpointClientAuthHandler) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	return client.GetRevocationEndpointAuthSigningAlg()
}

func (h *RevocationEndpointClientAuthHandler) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *RevocationEndpointClientAuthHandler) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

func (h *RevocationEndpointClientAuthHandler) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

func (h *RevocationEndpointClientAuthHandler) Name() string {
	return "revocation"
}

func (h *RevocationEndpointClientAuthHandler) AllowAuthMethodAny() bool {
	return true
}

type PushedAuthorizationRequestEndpointClientAuthHandler struct{}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthMethod(client AuthenticationMethodClient) string {
	if method := client.GetPushedAuthorizationRequestEndpointAuthMethod(); method != "" {
		return method
	}

	return client.GetTokenEndpointAuthMethod()
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthSigningKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthSigningAlg(client AuthenticationMethodClient) string {
	if alg := client.GetPushedAuthorizationRequestEndpointAuthSigningAlg(); alg != "" {
		return alg
	}

	return client.GetTokenEndpointAuthSigningAlg()
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthEncryptionKeyID(client AuthenticationMethodClient) string {
	return ""
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthEncryptionAlg(client AuthenticationMethodClient) string {
	return ""
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) GetAuthEncryptionEnc(client AuthenticationMethodClient) string {
	return ""
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) Name() string {
	return "pushed_authorization_request"
}

func (h *PushedAuthorizationRequestEndpointClientAuthHandler) AllowAuthMethodAny() bool {
	return false
}

// PrivateKey properly describes crypto.PrivateKey.
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}
