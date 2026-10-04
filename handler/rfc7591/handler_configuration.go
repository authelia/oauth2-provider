// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientConfigurationHandler implements oauth2.RFC7592ClientConfigurationEndpointHandler, RFC 7592's client
// configuration endpoint. It dispatches on the requester's HTTP method between reading (GET), replacing (PUT), and
// deleting (DELETE) a client.
type ClientConfigurationHandler struct {
	// Store persists the registered client and the registration access token's session.
	Store Storage

	// Strategy mints the client registration access tokens this handler issues.
	Strategy ClientRegistrationTokenStrategy

	// Config supplies the client registration strategy, validators, endpoint URL, and token entropy this handler
	// needs.
	Config Configurator
}

// HandleRFC7592ClientConfigurationEndpointRequest implements oauth2.RFC7592ClientConfigurationEndpointHandler. It
// returns oauth2.ErrNotFound when the client does not exist and oauth2.ErrInvalidRequest for a method other than GET,
// PUT, or DELETE.
func (h *ClientConfigurationHandler) HandleRFC7592ClientConfigurationEndpointRequest(ctx context.Context, requester oauth2.ClientConfigurationRequester, responder oauth2.ClientConfigurationResponder) (err error) {
	id := requester.GetClientID()

	var client oauth2.Client

	if client, err = h.Store.GetClient(ctx, id); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return errorsx.WithStack(oauth2.ErrNotFound.WithWrap(err).WithDebugError(err))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
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

// update implements the PUT case, RFC 7592 Section 2.2's full replacement semantics. The replacement registration
// access token is minted before the old one's session is deleted, so a failed mint leaves the client holding a working
// token.
func (h *ClientConfigurationHandler) update(ctx context.Context, id string, client oauth2.Client, requester oauth2.ClientConfigurationRequester, responder oauth2.ClientConfigurationResponder) (err error) {
	strategy := h.Config.GetRFC7591ClientRegistrationStrategy(ctx)
	if strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("No RFC 7591 client registration strategy is configured."))
	}

	metadata := requester.GetMetadata()

	// A PUT must carry metadata; GetMetadata is nil for GET and DELETE.
	// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.2
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

	if err = CheckGrantableResource(ctx, h.Config, requester.GetAuthenticatedRequester(), metadata); err != nil {
		return err
	}

	if err = CheckAuthorizationDetailsTypes(ctx, h.Config, metadata); err != nil {
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
	grantableResource := oauth2.Arguments(nil)

	// The authenticated requester carries the client registration token's own grant; a custom
	// oauth2.ClientRegistrationEndpointAuthStrategy must honour the same contract.
	if authenticated := requester.GetAuthenticatedRequester(); authenticated != nil {
		grantable = authenticated.GetGrantedScopes()
		grantableAudience = authenticated.GetGrantedAudience()
		grantableResource = authenticated.GetGrantedResource()
	}

	// The registration scope is never carried forward onto the rotated management token, even if the token
	// authenticating this update somehow held it: see ExcludeRegistrationScope.
	grantable = ExcludeRegistrationScope(ctx, h.Config, grantable)

	var token string

	if token, err = NewClientManagementToken(ctx, h.Strategy, h.Store, h.Config, patched, grantable, grantableAudience, grantableResource); err != nil {
		// The replacement client metadata is already persisted, but no replacement token was minted. The client's
		// existing management token (not yet deleted, see below) still works, so nothing is lost.
		return err
	}

	// The old session is deleted only after the replacement token is minted. A failed delete does not fail the request,
	// as the client already holds the new token.
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

// checkClientIDAndSecret validates the 'client_id' and 'client_secret' parameters RFC 7592 Section 2.2 permits in a PUT
// body, which arrive in metadata.Extra. A present 'client_id' must match the target id and a present 'client_secret'
// must match the client's current secret. Both keys are deleted from Extra so neither is persisted.
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

// delete implements the DELETE case: it removes the client and its registration session and responds 204 with an empty
// body. Deleting the session is best-effort, as the client is already gone.
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
