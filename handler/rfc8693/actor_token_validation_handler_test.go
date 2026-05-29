// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestActorTokenValidationHandler_Impersonation(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	req := newActorValidationRequest(t, newConfidentialClient(), map[string]any{
		consts.ClaimSubject: "alice",
	}, nil)

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), req))
}

func TestActorTokenValidationHandler_DelegationWithMayActMatchingActor(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	req := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{
			consts.ClaimSubject: "alice",
			consts.ClaimAuthorizedActor: map[string]any{
				consts.ClaimSubject: "bob",
			},
		},
		map[string]any{consts.ClaimSubject: "bob"},
	)

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), req))
}

func TestActorTokenValidationHandler_DelegationWithMayActMismatchedActor(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	req := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{
			consts.ClaimSubject: "alice",
			consts.ClaimAuthorizedActor: map[string]any{
				consts.ClaimSubject: "bob",
			},
		},
		map[string]any{consts.ClaimSubject: "eve"},
	)

	err := h.HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

func TestActorTokenValidationHandler_MayActWithoutActorTokenUsesClientAsActor(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	client := newConfidentialClient()

	// may_act says the actor's sub must equal the authenticated client's id.
	req := newActorValidationRequest(t, client,
		map[string]any{
			consts.ClaimSubject: "alice",
			consts.ClaimAuthorizedActor: map[string]any{
				consts.ClaimSubject:          client.GetID(),
				consts.ClaimClientIdentifier: client.GetID(),
			},
		},
		nil,
	)

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), req))
}

// Regression: previously the may_act/actor comparison used interface == which panics when either side has a
// dynamic type that is not comparable (slice, map, struct with unexportable fields). Real may_act payloads can
// carry array/object values (e.g. aud lists, nested role objects). The handler must use a deep, comparison-safe
// equality check and not panic.
func TestActorTokenValidationHandler_HandlesNonScalarMayActWithoutPanic(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	// Matching case: may_act constrains 'roles' to a slice, actor matches.
	req := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{
			consts.ClaimSubject: "alice",
			consts.ClaimAuthorizedActor: map[string]any{
				consts.ClaimSubject: "bob",
				"roles":             []any{"admin", "editor"},
			},
		},
		map[string]any{
			consts.ClaimSubject: "bob",
			"roles":             []any{"admin", "editor"},
		},
	)

	require.NotPanics(t, func() {
		require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), req))
	})

	// Mismatched non-scalar: must reject cleanly (no panic), with invalid_grant.
	reqMismatch := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{
			consts.ClaimSubject: "alice",
			consts.ClaimAuthorizedActor: map[string]any{
				consts.ClaimSubject: "bob",
				"roles":             []any{"admin"},
			},
		},
		map[string]any{
			consts.ClaimSubject: "bob",
			"roles":             []any{"viewer"},
		},
	)

	var err error
	require.NotPanics(t, func() {
		err = h.HandleTokenEndpointRequest(context.Background(), reqMismatch)
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

func TestActorTokenValidationHandler_RejectsActorTokenWithoutMayAct(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	req := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{consts.ClaimSubject: "alice"},
		map[string]any{consts.ClaimSubject: "bob"},
	)

	err := h.HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "subject token does not authorize delegation")
}

func TestActorTokenValidationHandler_AllowsActorTokenWithoutMayActWhenPolicyOptsIn(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	client := &rfc8693Client{DefaultClient: newConfidentialClient(), allow: true}

	req := newActorValidationRequest(t, client,
		map[string]any{consts.ClaimSubject: "alice"},
		map[string]any{consts.ClaimSubject: "bob"},
	)

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), req))
}

func TestActorTokenValidationHandler_RejectsWhenPolicyClientReturnsFalse(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	client := &rfc8693Client{DefaultClient: newConfidentialClient(), allow: false}

	req := newActorValidationRequest(t, client,
		map[string]any{consts.ClaimSubject: "alice"},
		map[string]any{consts.ClaimSubject: "bob"},
	)

	err := h.HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

// =============================================================================
// Test helpers
// =============================================================================

func newActorValidationRequest(t *testing.T, client oauth2.Client, subject, actor map[string]any) *oauth2.AccessRequest {
	t.Helper()

	session := &DefaultSession{}
	if subject != nil {
		session.SetSubjectToken(subject)
	}

	if actor != nil {
		session.SetActorToken(actor)
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			Client:  client,
			Session: session,
		},
	}
}
