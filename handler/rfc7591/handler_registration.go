// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/randx"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Configurator is the configuration seam consumed by ClientRegistrationHandler.
type Configurator interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
	oauth2.RFC7591ClientRegistrationPolicyProvider
	oauth2.TokenEntropyProvider
	oauth2.ScopeStrategyProvider
	oauth2.AudienceStrategyProvider
	oauth2.ResourceStrategyProvider
	oauth2.JWKSFetcherStrategyProvider

	ClientRegistrationMetadataStrategyConfig
}

// ClientRegistrationHandler implements oauth2.RFC7591ClientRegistrationEndpointHandler, RFC 7591 Section 3.1's client
// registration endpoint. The client secret it generates is plaintext; a deployment that wants secrets hashed at rest
// supplies its own oauth2.ClientRegistrationStrategy.
type ClientRegistrationHandler struct {
	// Store persists the registered client and the registration access token's session.
	Store Storage

	// Strategy mints the client registration access tokens this handler issues.
	Strategy ClientRegistrationTokenStrategy

	// Config supplies the client registration strategy, validators, endpoint URL, secret lifespan, and token
	// entropy this handler needs.
	Config Configurator
}

// HandleRFC7591ClientRegistrationEndpointRequest implements oauth2.RFC7591ClientRegistrationEndpointHandler. If minting
// the registration access token fails the persisted client is deleted. The response metadata is rendered from the
// persisted client rather than echoing the request.
//
// When the authenticating token carries a registration policy, the policy replaces the token's granted scope, audience
// and resource as the bound on the client, its 'max_registrations' slot is reserved immediately before the client is
// persisted and released if persisting or minting fails, and the minted management token carries the policy.
func (h *ClientRegistrationHandler) HandleRFC7591ClientRegistrationEndpointRequest(ctx context.Context, requester oauth2.ClientRegistrationRequester, responder oauth2.ClientRegistrationResponder) (err error) {
	strategy := h.Config.GetRFC7591ClientRegistrationStrategy(ctx)
	if strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("No RFC 7591 client registration strategy is configured."))
	}

	metadata := requester.GetMetadata()

	// ClientRegistrationRequester is an extension point, so nil metadata is rejected rather than dereferenced.
	if metadata == nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The request did not contain any client metadata."))
	}

	// The software statement is verified and merged first, so the filter, the validators and the registration policy
	// all judge the metadata the client will be registered with.
	if err = applySoftwareStatement(ctx, h.Config, metadata); err != nil {
		return err
	}

	filter := metadataStrategy(ctx, h.Config)

	// Filtering precedes validation and the secret decision below: metadata for a disabled feature must not be
	// validated against, must not select an authentication method, and must not reach the registration strategy.
	if err = filter.FilterClientRegistrationMetadata(ctx, nil, metadata); err != nil {
		return err
	}

	dropUnrecognisedMetadata(ctx, h.Config, metadata)

	for _, validator := range validators(ctx, h.Config) {
		if err = validator.ValidateClientRegistrationMetadata(ctx, nil, metadata); err != nil {
			return err
		}
	}

	authenticated := requester.GetAuthenticatedRequester()

	var (
		policy *RegistrationPolicy
		key    string
	)

	if policy, key, err = registrationPolicy(ctx, h.Config, authenticated); err != nil {
		return err
	}

	// A token carrying a registration policy is bounded by the policy alone, never by its own granted scope, audience
	// or resource; a registration scope stays unobtainable either way.
	if policy != nil {
		if err = policy.Check(metadata); err != nil {
			return err
		}

		if err = rejectRegistrationScopes(ctx, h.Config, metadata); err != nil {
			return err
		}
	} else {
		if err = CheckGrantableScopes(ctx, h.Config, authenticated, metadata); err != nil {
			return err
		}

		if err = CheckGrantableAudience(ctx, h.Config, authenticated, metadata); err != nil {
			return err
		}

		if err = CheckGrantableResource(ctx, h.Config, authenticated, metadata); err != nil {
			return err
		}
	}

	if err = CheckAuthorizationDetailsTypes(ctx, h.Config, metadata); err != nil {
		return err
	}

	// Unconditional, and after the ceiling check rather than before it: an authenticated request asking for the
	// registration scope was already rejected above, while an unauthenticated (open) endpoint has no ceiling to
	// reject it with and would otherwise register a client holding it. See ExcludeRegistrationScopeFromMetadata.
	ExcludeRegistrationScopeFromMetadata(ctx, h.Config, metadata)

	if err = retainPresentSoftwareStatementMembers(metadata); err != nil {
		return err
	}

	var idSeq []rune

	if idSeq, err = randx.RuneSequence(ClientIDEntropy, randx.AlphaNum); err != nil {
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

	// RFC 7591 Section 3.2.1: 'client_id_issued_at' and 'client_secret_expires_at' are the values recorded on the
	// client before it is persisted, so the expiry stated is the one CompareClientSecret enforces. A client type that
	// cannot carry an expiry is advertised none.
	var (
		now             = time.Now().UTC()
		issuedAt        = now
		secretExpiresAt time.Time
	)

	if issued, ok := client.(oauth2.ClientIDIssuedAtClient); ok {
		issuedAt = issued.GetClientIDIssuedAt()
	}

	if lifespan := h.Config.GetRFC7591ClientSecretLifespan(ctx); lifespan > 0 && len(plainSecret) != 0 {
		if registered, ok := client.(*oauth2.DefaultRegisteredClient); ok {
			if issuedAt.IsZero() {
				secretExpiresAt = now.Add(lifespan)
			} else {
				secretExpiresAt = issuedAt.Add(lifespan)
			}

			registered.ClientSecretExpiresAt = secretExpiresAt
		}
	}

	var counter oauth2.ClientRegistrationCounterStorage

	if counter, err = h.reserveRegistration(ctx, policy, key); err != nil {
		return err
	}

	// Compensation runs without the request's cancellation, which would otherwise spend the slot or orphan the client.
	compensationCtx := context.WithoutCancel(ctx)

	release := func() (err error) {
		if counter == nil {
			return nil
		}

		return counter.ReleaseClientRegistration(compensationCtx, key)
	}

	if err = h.Store.CreateClient(ctx, client); err != nil {
		if relErr := release(); relErr != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Failed to persist the client: %s. Releasing the registration counter slot also failed: %s.", err, relErr))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	registrationClientURI := ClientConfigurationURL(h.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), id)

	var token string

	if policy != nil {
		token, err = NewClientManagementTokenWithPolicy(ctx, h.Strategy, h.Store, h.Config, client, policy.WithoutMaxRegistrations())
	} else {
		grantable := metadata.GetScopes()
		grantableAudience := oauth2.Arguments(metadata.Audience)
		grantableResource := oauth2.Arguments(metadata.Resource)

		if authenticated != nil {
			grantable = authenticated.GetGrantedScopes()
			grantableAudience = authenticated.GetGrantedAudience()
			grantableResource = authenticated.GetGrantedResource()
		}

		// The registration scope is never carried forward onto the minted management token, even though every
		// legitimate creation token holds it: see ExcludeRegistrationScope.
		grantable = ExcludeRegistrationScope(ctx, h.Config, grantable)

		token, err = NewClientManagementToken(ctx, h.Strategy, h.Store, h.Config, client, grantable, grantableAudience, grantableResource)
	}

	if err != nil {
		// A persisted client with no management token is unmanageable: delete it, release its registration counter slot
		// and return the original error, noting any failed compensation in the debug field. The slot is kept while the
		// client still exists, so a failed deletion cannot take the token past its limit.
		var compensation []string

		if delErr := h.Store.DeleteClient(compensationCtx, id); delErr != nil {
			compensation = append(compensation, fmt.Sprintf("Compensating deletion of client '%s' also failed: %s.", id, delErr))

			if counter != nil {
				compensation = append(compensation, "The registration counter slot was retained.")
			}
		} else if relErr := release(); relErr != nil {
			compensation = append(compensation, fmt.Sprintf("Releasing the registration counter slot also failed: %s.", relErr))
		}

		if len(compensation) != 0 {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Failed to mint the client registration token: %s. %s", err, strings.Join(compensation, " ")))
		}

		return err
	}

	var responseMetadata *oauth2.ClientRegistrationMetadata

	if responseMetadata, err = strategy.MetadataFromClient(ctx, client); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = filter.FilterClientRegistrationMetadata(ctx, client, responseMetadata); err != nil {
		return err
	}

	responder.SetMetadata(responseMetadata)
	responder.SetClientID(id)
	responder.SetClientSecret(plainSecret)
	responder.SetClientIDIssuedAt(issuedAt)

	// RFC 7591 Section 3.2.1: 'client_secret_expires_at' is only reported alongside a 'client_secret'.
	if !secretExpiresAt.IsZero() {
		responder.SetClientSecretExpiresAt(secretExpiresAt)
	}

	responder.SetRegistrationAccessToken(token)
	responder.SetRegistrationClientURI(registrationClientURI)
	responder.SetStatusCode(http.StatusCreated)

	return nil
}

func (h *ClientRegistrationHandler) reserveRegistration(ctx context.Context, policy *RegistrationPolicy, key string) (counter oauth2.ClientRegistrationCounterStorage, err error) {
	if policy == nil || policy.MaxRegistrations() <= 0 {
		return nil, nil
	}

	var ok bool

	// The limit is never silently skipped: storage that cannot count fails the request.
	if counter, ok = h.Store.(oauth2.ClientRegistrationCounterStorage); !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The registration policy sets 'max_registrations' but the storage does not implement oauth2.ClientRegistrationCounterStorage."))
	}

	if key == "" {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The registration policy sets 'max_registrations' but the presented Client Registration Token has no registration counter key."))
	}

	if err = counter.ReserveClientRegistration(ctx, key, policy.MaxRegistrations()); err != nil {
		// RFC 7591 Section 3.2.2: a spent token is an error of the token, reported as RFC 6750 Section 3.1 'invalid_token'.
		if errors.Is(err, oauth2.ErrClientRegistrationLimitReached) {
			return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The presented Client Registration Token has reached its registration limit.").WithWrap(err))
		}

		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return counter, nil
}

func registrationPolicy(ctx context.Context, config Configurator, authenticated oauth2.Requester) (policy *RegistrationPolicy, key string, err error) {
	if authenticated == nil {
		return nil, "", nil
	}

	requester, ok := authenticated.(RegistrationPolicyRequester)
	if !ok {
		return nil, "", nil
	}

	claim, ok := requester.GetRegistrationPolicyClaim()
	if !ok {
		return nil, "", nil
	}

	if policy, err = ParseRegistrationPolicy(claim, customMetadata(ctx, config), requester.GetRegistrationPolicyPatternsPermitted()); err != nil {
		return nil, "", err
	}

	return policy, requester.GetRegistrationCounterKey(), nil
}

var (
	_ oauth2.RFC7591ClientRegistrationEndpointHandler = (*ClientRegistrationHandler)(nil)
)
