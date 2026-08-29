// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientConfigurationHandler implements oauth2.RFC7592ClientConfigurationEndpointHandler, RFC 7592's client
// configuration endpoint. One handler serves the whole endpoint, dispatching on the requester's HTTP method between
// reading (GET), replacing (PUT), and deleting (DELETE) a client - the same shape ClientRegistrationHandler's
// sibling handler uses for the client registration endpoint.
type ClientConfigurationHandler struct {
	// Store persists the registered client and the registration access token's session.
	Store Storage

	// Strategy mints the client registration access tokens this handler issues.
	Strategy ClientRegistrationTokenStrategy

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

	// Load-bearing here, unlike the registration and update paths: this client may have been registered while a
	// feature was enabled and read back after it was disabled, and nothing else filters it.
	if err = metadataStrategy(ctx, h.Config).FilterClientRegistrationMetadata(ctx, client, metadata); err != nil {
		return err
	}

	id := client.GetID()

	responder.SetMetadata(metadata)
	responder.SetClientID(id)
	responder.SetRegistrationClientURI(ClientConfigurationURL(h.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), id))

	if secret, ok, serr := client.GetClientSecretPlainText(); serr == nil && ok {
		responder.SetClientSecret(string(secret))
	}

	setRegistrationTimes(client, responder)

	responder.SetStatusCode(http.StatusOK)

	return nil
}

// setRegistrationTimes reports the RFC 7591 Section 3.2.1 registration bookkeeping values for client. Both are read
// from the client rather than recomputed: 'client_id_issued_at' records when the identifier was issued, and
// 'client_secret_expires_at' is enforced by CompareClientSecret, so reporting a zero here would tell the client its
// secret does not expire when it does.
func setRegistrationTimes(client oauth2.Client, responder oauth2.ClientConfigurationResponder) {
	if issued, ok := client.(oauth2.ClientIDIssuedAtClient); ok {
		responder.SetClientIDIssuedAt(issued.GetClientIDIssuedAt())
	}

	if expiring, ok := client.(oauth2.ExpiringClientSecretClient); ok {
		responder.SetClientSecretExpiresAt(expiring.GetClientSecretExpiresAt())
	}
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

	// ClientConfigurationRequester documents GetMetadata as nil for GET and DELETE, so a PUT arriving with none is a
	// shape the interface itself makes reachable: reject it before the metadata is filtered, checked, and validated
	// rather than dereferencing it. RFC 7592 Section 2.2 replacement semantics also make an empty PUT the wrong
	// thing to treat as "nothing to change" - it would replace the client's entire metadata with nothing.
	if metadata == nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The request did not contain any client metadata."))
	}

	filter := metadataStrategy(ctx, h.Config)

	if err = filter.FilterClientRegistrationMetadata(ctx, client, metadata); err != nil {
		return err
	}

	if err = h.checkClientIDAndSecret(ctx, id, client, metadata); err != nil {
		return err
	}

	for _, validator := range validators(ctx, h.Config) {
		if err = validator.ValidateClientRegistrationMetadata(ctx, client, metadata); err != nil {
			return err
		}
	}

	if err = CheckGrantableScopes(ctx, h.Config, requester.GetAuthenticatedRequester(), metadata); err != nil {
		return err
	}

	if err = CheckGrantableAudience(ctx, h.Config, requester.GetAuthenticatedRequester(), metadata); err != nil {
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
	grantableAudience := oauth2.Arguments(nil)

	// The authenticated requester came from the configured oauth2.ClientRegistrationEndpointAuthStrategy, whose sole
	// contract is authenticating client registration tokens - this package's own DefaultEndpointAuthStrategy resolves
	// it from the client registration token store, a storage namespace separate from ordinary access tokens, so a
	// requester reaching this point through it always carries a genuine client registration token's own grant. A
	// deployment supplying its own implementation of that interface is expected to honour the same contract.
	if authenticated := requester.GetAuthenticatedRequester(); authenticated != nil {
		grantable = authenticated.GetGrantedScopes()
		grantableAudience = authenticated.GetGrantedAudience()
	}

	// The registration scope is never carried forward onto the rotated management token, even if the token
	// authenticating this update somehow held it: see ExcludeRegistrationScope.
	grantable = ExcludeRegistrationScope(ctx, h.Config, grantable)

	var token string

	if token, err = NewClientManagementToken(ctx, h.Strategy, h.Store, h.Config, patched, grantable, grantableAudience); err != nil {
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
		_ = h.Store.DeleteClientRegistrationTokenSession(ctx, oldSignature)
	}

	var responseMetadata *oauth2.ClientRegistrationMetadata

	if responseMetadata, err = strategy.MetadataFromClient(ctx, patched); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = filter.FilterClientRegistrationMetadata(ctx, patched, responseMetadata); err != nil {
		return err
	}

	responder.SetMetadata(responseMetadata)
	responder.SetClientID(id)

	if secret, ok, serr := patched.GetClientSecretPlainText(); serr == nil && ok {
		responder.SetClientSecret(string(secret))
	}

	responder.SetRegistrationAccessToken(token)
	responder.SetRegistrationClientURI(registrationClientURI)

	setRegistrationTimes(patched, responder)

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
		_ = h.Store.DeleteClientRegistrationTokenSession(ctx, signature)
	}

	responder.SetMetadata(nil)
	responder.SetStatusCode(http.StatusNoContent)

	return nil
}

var (
	_ oauth2.RFC7592ClientConfigurationEndpointHandler = (*ClientConfigurationHandler)(nil)
)
