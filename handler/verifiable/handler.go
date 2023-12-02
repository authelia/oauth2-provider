// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/authelia/goauth2"
)

const (
	draftScope         = "userinfo_credential_draft_00"
	draftNonceField    = "c_nonce_draft_00"
	draftNonceExpField = "c_nonce_expires_in_draft_00"
)

type Handler struct {
	Config interface {
		goauth2.VerifiableCredentialsNonceLifespanProvider
	}
	NonceManager
}

var _ goauth2.TokenEndpointHandler = (*Handler)(nil)

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(
	ctx context.Context,
	request goauth2.AccessRequester,
	response goauth2.AccessResponder,
) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	lifespan := c.Config.GetVerifiableCredentialsNonceLifespan(ctx)
	expiry := time.Now().UTC().Add(lifespan)
	nonce, err := c.NewNonce(ctx, response.GetAccessToken(), expiry)
	if err != nil {
		return err
	}

	response.SetExtra(draftNonceField, nonce)
	response.SetExtra(draftNonceExpField, int64(lifespan.Seconds()))

	return nil
}

func (c *Handler) CanSkipClientAuth(context.Context, goauth2.AccessRequester) bool {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(_ context.Context, requester goauth2.AccessRequester) bool {
	return requester.GetGrantedScopes().Has("openid", draftScope)
}
