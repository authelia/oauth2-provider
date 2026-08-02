// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/randx"
	"authelia.com/provider/oauth2/x/errorsx"
)

// clientIDEntropy is the number of alphanumeric runes generated for a new 'client_id'.
const clientIDEntropy = 32

// Configurator is the configuration seam consumed by ClientRegistrationHandler.
type Configurator interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
	oauth2.TokenEntropyProvider
	oauth2.ScopeStrategyProvider
}

var (
	_ oauth2.RFC7591ClientRegistrationEndpointHandler = (*ClientRegistrationHandler)(nil)
)

// ClientRegistrationHandler implements oauth2.RFC7591ClientRegistrationEndpointHandler, RFC 7591 Section 3.1's
// client registration endpoint. It generates the client_id (and, unless the submitted metadata requests the "none"
// token_endpoint_auth_method, a client secret), delegates construction of the concrete client to the configured
// oauth2.ClientRegistrationStrategy, persists the client, and mints the RFC 7592 registration access token used to
// manage it afterwards.
//
// The client secret this handler generates is plaintext entropy wrapped with oauth2.NewPlainTextClientSecret. That
// is the default, not a recommendation: a deployment that wants secrets hashed at rest supplies its own
// oauth2.ClientRegistrationStrategy (via Configurator's GetRFC7591ClientRegistrationStrategy) that generates and
// stores the secret however it sees fit; this handler only ever receives the ClientSecret that strategy is given
// to embed on the client it constructs.
type ClientRegistrationHandler struct {
	// Store persists the registered client and the registration access token's session.
	Store Storage

	// Strategy mints the client registration access tokens this handler issues.
	Strategy hoauth2.AccessTokenStrategy

	// Config supplies the client registration strategy, validators, endpoint URL, secret lifespan, and token
	// entropy this handler needs.
	Config Configurator
}

// HandleRFC7591ClientRegistrationEndpointRequest implements oauth2.RFC7591ClientRegistrationEndpointHandler.
//
// It performs, in order: (1) confirms a client registration strategy is configured, (2) runs every configured
// validator against the submitted metadata with a nil client, (3) enforces the requesting creation token's scope
// ceiling, if any, against the requested scopes, (4) generates the client_id, (5) generates a plaintext client
// secret unless the metadata's token_endpoint_auth_method is "none", (6) constructs the concrete client via the
// strategy, (7) persists it, (8) mints and persists the registration access token - compensating with a client
// delete if that fails, since a client nobody holds a token for is permanently unmanageable - and (9) populates
// the responder, re-rendering the metadata from the persisted client so server-applied values are reflected
// rather than echoing the request.
func (h *ClientRegistrationHandler) HandleRFC7591ClientRegistrationEndpointRequest(ctx context.Context, requester oauth2.ClientRegistrationRequester, responder oauth2.ClientRegistrationResponder) (err error) {
	strategy := h.Config.GetRFC7591ClientRegistrationStrategy(ctx)
	if strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("No RFC 7591 client registration strategy is configured."))
	}

	metadata := requester.GetMetadata()

	for _, validator := range h.Config.GetRFC7591ClientRegistrationValidators(ctx) {
		if err = validator.ValidateClientRegistrationMetadata(ctx, nil, metadata); err != nil {
			return err
		}
	}

	if err = checkGrantableScopes(ctx, h.Config, requester.GetAuthenticatedRequester(), metadata); err != nil {
		return err
	}

	var idSeq []rune

	if idSeq, err = randx.RuneSequence(clientIDEntropy, randx.AlphaNum); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	id := string(idSeq)

	// Unless the client requests the "none" token_endpoint_auth_method, generate a plaintext client secret. A
	// deployment wanting hashed storage supplies its own oauth2.ClientRegistrationStrategy; see the type doc.
	var (
		secret      oauth2.ClientSecret
		plainSecret string
	)

	if metadata.TokenEndpointAuthMethod != consts.ClientAuthMethodNone {
		var secretSeq []rune

		if secretSeq, err = randx.RuneSequence(h.Config.GetTokenEntropy(ctx), randx.AlphaNum); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		plainSecret = string(secretSeq)
		secret = oauth2.NewPlainTextClientSecret(plainSecret)
	}

	var client oauth2.Client

	if client, err = strategy.NewClient(ctx, id, secret, metadata); err != nil {
		return err
	}

	if err = h.Store.CreateClient(ctx, client); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	registrationClientURI := ClientConfigurationURL(h.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), id)

	grantable := metadata.GetScopes()

	if authenticated := requester.GetAuthenticatedRequester(); authenticated != nil {
		if session, ok := authenticated.GetSession().(Session); ok && session.IsClientRegistration() {
			grantable = session.GetGrantableScopes()
		}
	}

	var token string

	if token, err = NewClientManagementToken(ctx, h.Strategy, h.Store, h.Config, client, grantable); err != nil {
		// The client was persisted but nobody holds a token to manage it: it would be permanently unmanageable and
		// its client_id burned. Compensate by deleting it before returning the original error. If the compensating
		// delete itself fails, prefer the original error and note the cleanup failure in the debug field rather
		// than masking the root cause.
		if delErr := h.Store.DeleteClient(ctx, id); delErr != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Failed to mint the client registration token: %s. Compensating deletion of client '%s' also failed: %s.", err, id, delErr))
		}

		return err
	}

	var responseMetadata *oauth2.ClientRegistrationMetadata

	if responseMetadata, err = strategy.MetadataFromClient(ctx, client); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	responder.SetMetadata(responseMetadata)
	responder.SetClientID(id)
	responder.SetClientSecret(plainSecret)
	responder.SetClientIDIssuedAt(time.Now().UTC())

	if lifespan := h.Config.GetRFC7591ClientSecretLifespan(ctx); lifespan > 0 {
		responder.SetClientSecretExpiresAt(time.Now().UTC().Add(lifespan))
	}

	responder.SetRegistrationAccessToken(token)
	responder.SetRegistrationClientURI(registrationClientURI)
	responder.SetStatusCode(http.StatusCreated)

	return nil
}
