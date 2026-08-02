// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

var (
	_ oauth2.RFC7592ClientConfigurationEndpointHandler = (*ClientConfigurationHandler)(nil)
)

// ClientConfigurationHandler implements oauth2.RFC7592ClientConfigurationEndpointHandler, RFC 7592's client
// configuration endpoint. One handler serves the whole endpoint, dispatching on the requester's HTTP method between
// reading (GET), replacing (PUT), and deleting (DELETE) a client - the same shape ClientRegistrationHandler's
// sibling handler uses for the client registration endpoint.
type ClientConfigurationHandler struct {
	// Store persists the registered client and the registration access token's session.
	Store Storage

	// Strategy mints the client registration access tokens this handler issues.
	Strategy hoauth2.AccessTokenStrategy

	// Config supplies the client registration strategy, validators, endpoint URL, and token entropy this handler
	// needs.
	Config Configurator
}

// HandleRFC7592ClientConfigurationEndpointRequest implements oauth2.RFC7592ClientConfigurationEndpointHandler.
//
// It loads the client named by requester.GetClientID(), returning oauth2.ErrNotFound when no such client exists,
// then dispatches on requester.GetMethod() to read, update, or delete. A method other than GET, PUT, or DELETE
// yields oauth2.ErrInvalidRequest naming the method, which the RFC 7592 response writer (Task 15) maps to 405.
func (h *ClientConfigurationHandler) HandleRFC7592ClientConfigurationEndpointRequest(ctx context.Context, requester oauth2.ClientConfigurationRequester, responder oauth2.ClientConfigurationResponder) (err error) {
	id := requester.GetClientID()

	var client oauth2.Client

	if client, err = h.Store.GetClient(ctx, id); err != nil {
		return errorsx.WithStack(oauth2.ErrNotFound.WithWrap(err).WithDebugError(err))
	}

	switch requester.GetMethod() {
	case http.MethodGet:
		return h.read(ctx, client, responder)
	case http.MethodPut:
		return h.update(ctx, id, client, requester, responder)
	case http.MethodDelete:
		return h.delete(ctx, id, requester, responder)
	default:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The client configuration endpoint does not support the '%s' method.", requester.GetMethod()))
	}
}

// read implements the GET case: it renders the client's current metadata, status 200. The 'client_secret' is
// included only when the client exposes one in plaintext; a hashed-secret store simply omits it. The presented
// registration access token is deliberately not re-emitted: only its signature reaches this handler (see
// DefaultEndpointAuthStrategy), and a signature cannot be turned back into the token it was derived from.
func (h *ClientConfigurationHandler) read(ctx context.Context, client oauth2.Client, responder oauth2.ClientConfigurationResponder) (err error) {
	strategy := h.Config.GetRFC7591ClientRegistrationStrategy(ctx)
	if strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("No RFC 7591 client registration strategy is configured."))
	}

	var metadata *oauth2.ClientRegistrationMetadata

	if metadata, err = strategy.MetadataFromClient(ctx, client); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	id := client.GetID()

	responder.SetMetadata(metadata)
	responder.SetClientID(id)
	responder.SetRegistrationClientURI(ClientConfigurationURL(h.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), id))

	if secret, ok, serr := client.GetClientSecretPlainText(); serr == nil && ok {
		responder.SetClientSecret(string(secret))
	}

	responder.SetStatusCode(http.StatusOK)

	return nil
}

// update implements the PUT case, RFC 7592 Section 2.2's full replacement semantics: 'client_id' and 'client_secret'
// arrive as unregistered metadata parameters (see PatchClient's doc comment), are validated and stripped from Extra
// so they are never persisted as unregistered client metadata, the remaining metadata is validated and applied as a
// complete replacement, and finally a replacement registration access token is minted before the old one's session
// is deleted - in that order, so a failure minting the replacement leaves the client still holding a working token
// rather than locked out of its own registration.
func (h *ClientConfigurationHandler) update(ctx context.Context, id string, client oauth2.Client, requester oauth2.ClientConfigurationRequester, responder oauth2.ClientConfigurationResponder) (err error) {
	strategy := h.Config.GetRFC7591ClientRegistrationStrategy(ctx)
	if strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("No RFC 7591 client registration strategy is configured."))
	}

	metadata := requester.GetMetadata()

	if err = h.checkClientIDAndSecret(ctx, id, client, metadata); err != nil {
		return err
	}

	for _, validator := range h.Config.GetRFC7591ClientRegistrationValidators(ctx) {
		if err = validator.ValidateClientRegistrationMetadata(ctx, client, metadata); err != nil {
			return err
		}
	}

	if err = checkGrantableScopes(ctx, h.Config, requester.GetAuthenticatedRequester(), metadata); err != nil {
		return err
	}

	var patched oauth2.Client

	if patched, err = strategy.PatchClient(ctx, client, nil, metadata); err != nil {
		return err
	}

	if err = h.Store.UpdateClient(ctx, id, patched); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	registrationClientURI := ClientConfigurationURL(h.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), id)

	grantable := oauth2.Arguments(nil)

	// IsClientRegistration is required as well as the type assertion, matching ClientRegistrationHandler and
	// checkGrantableScopes: a session may satisfy Session and still be an ordinary access token's, in which case its
	// zero-valued GrantableScopes is not a ceiling and must not be carried onto the rotated token.
	if authenticated := requester.GetAuthenticatedRequester(); authenticated != nil {
		if session, ok := authenticated.GetSession().(Session); ok && session.IsClientRegistration() {
			grantable = session.GetGrantableScopes()
		}
	}

	var token string

	if token, err = NewClientManagementToken(ctx, h.Strategy, h.Store, h.Config, patched, grantable); err != nil {
		// The replacement client metadata is already persisted, but no replacement token was minted. The client's
		// existing management token (not yet deleted, see below) still works, so nothing is lost.
		return err
	}

	// The replacement token above is minted before the old session is deleted here: if minting had failed, the
	// client would still hold a working token (returned above). Deleting first and having the mint then fail would
	// instead leave the client permanently locked out of its own registration. If this delete itself fails, the
	// client already holds the new, working token from the mint above, so that is preferred over failing the whole
	// request; the stale old session is otherwise harmless since it authenticates a client that continues to exist.
	if oldSignature := requester.GetSignature(); oldSignature != "" {
		_ = h.Store.DeleteAccessTokenSession(ctx, oldSignature)
	}

	var responseMetadata *oauth2.ClientRegistrationMetadata

	if responseMetadata, err = strategy.MetadataFromClient(ctx, patched); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	responder.SetMetadata(responseMetadata)
	responder.SetClientID(id)

	if secret, ok, serr := patched.GetClientSecretPlainText(); serr == nil && ok {
		responder.SetClientSecret(string(secret))
	}

	responder.SetRegistrationAccessToken(token)
	responder.SetRegistrationClientURI(registrationClientURI)
	responder.SetStatusCode(http.StatusOK)

	return nil
}

// checkClientIDAndSecret validates the 'client_id' and 'client_secret' pseudo-metadata parameters RFC 7592
// Section 2.2 permits in a PUT body. Neither is a registered ClientRegistrationMetadata field, so both arrive in
// metadata.Extra. A present 'client_id' must match the target id; a present 'client_secret' must match the client's
// current secret. Both keys are deleted from Extra once checked - whether or not they were present - so neither is
// ever persisted as unregistered client metadata.
func (h *ClientConfigurationHandler) checkClientIDAndSecret(ctx context.Context, id string, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata == nil || len(metadata.Extra) == 0 {
		return nil
	}

	if raw, ok := metadata.Extra[consts.ClientRegistrationResponseClientID]; ok {
		value, isString := raw.(string)

		if !isString || value != id {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The 'client_id' in the request body, if present, must match the client_id in the request path."))
		}

		delete(metadata.Extra, consts.ClientRegistrationResponseClientID)
	}

	if raw, ok := metadata.Extra[consts.ClientRegistrationResponseClientSecret]; ok {
		value, isString := raw.(string)

		secret := client.GetClientSecret()

		if !isString || secret == nil {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The 'client_secret' in the request body does not match the client's current secret."))
		}

		if err = secret.Compare(ctx, []byte(value)); err != nil {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The 'client_secret' in the request body does not match the client's current secret.").WithWrap(err).WithDebugError(err))
		}

		delete(metadata.Extra, consts.ClientRegistrationResponseClientSecret)
	}

	if len(metadata.Extra) == 0 {
		metadata.Extra = nil
	}

	return nil
}

// delete implements the DELETE case: it removes the client and its registration session and responds 204 with an
// empty body. Deleting the session is best-effort: if it fails after the client itself was successfully deleted,
// the client is already gone, so any subsequent request bearing the stale token fails at the client lookup anyway,
// and leaving the request otherwise successful is preferable to reporting failure for cleanup of a resource whose
// primary deletion already succeeded.
func (h *ClientConfigurationHandler) delete(ctx context.Context, id string, requester oauth2.ClientConfigurationRequester, responder oauth2.ClientConfigurationResponder) (err error) {
	if err = h.Store.DeleteClient(ctx, id); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if signature := requester.GetSignature(); signature != "" {
		_ = h.Store.DeleteAccessTokenSession(ctx, signature)
	}

	responder.SetMetadata(nil)
	responder.SetStatusCode(http.StatusNoContent)

	return nil
}
