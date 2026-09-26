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
	"authelia.com/provider/oauth2/token/jwt"
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
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestActorTokenValidationHandler_MayActWithoutActorTokenUsesClientAsActor(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	client := newConfidentialClient()

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

func TestActorTokenValidationHandler_HandlesNonScalarMayActWithoutPanic(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	t.Run("ShouldAcceptAMatchingNonScalarClaim", func(t *testing.T) {
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
	})

	t.Run("ShouldRejectAMismatchedNonScalarClaimWithoutPanicking", func(t *testing.T) {
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
		assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})
}

func TestActorTokenValidationHandler_RejectsActorTokenWithoutMayAct(t *testing.T) {
	h := &ActorTokenValidationHandler{}

	req := newActorValidationRequest(t, newConfidentialClient(),
		map[string]any{consts.ClaimSubject: "alice"},
		map[string]any{consts.ClaimSubject: "bob"},
	)

	err := h.HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The subject token does not authorize delegation: no 'may_act' claim is present. The OAuth 2.0 client supplied an 'actor_token' but the subject token does not contain a 'may_act' claim authorizing the actor to act on behalf of the subject. Either set the 'may_act' claim on the subject token, or configure the client to use an out-of-band authorization policy by implementing the ActorTokenPolicyClient interface.")
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
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestActorTokenValidationHandler_MayActFormat(t *testing.T) {
	testCases := []struct {
		name   string
		mayAct any
		actor  map[string]any
		err    bool
	}{
		{name: "ShouldRejectAStringWithoutAnActorToken", mayAct: "admin", err: true},
		{name: "ShouldRejectAnArrayWithoutAnActorToken", mayAct: []any{map[string]any{consts.ClaimSubject: "bob"}}, err: true},
		{name: "ShouldRejectANullWithoutAnActorToken", mayAct: nil, err: true},
		{name: "ShouldRejectAnEmptyObject", mayAct: map[string]any{}, actor: map[string]any{consts.ClaimSubject: "eve"}, err: true},
		{name: "ShouldRejectAnEmptyObjectWithoutAnActorToken", mayAct: map[string]any{}, err: true},
		{name: "ShouldRejectAnObjectWithOnlyUnusedClaims", mayAct: map[string]any{consts.ClaimExpirationTime: 1, consts.ClaimNotBefore: 1, consts.ClaimAudience: "x"}, actor: map[string]any{consts.ClaimSubject: "eve"}, err: true},
		{name: "ShouldIgnoreTheUnusedClaims", mayAct: map[string]any{consts.ClaimSubject: "bob", consts.ClaimExpirationTime: 1, consts.ClaimNotBefore: 1, consts.ClaimAudience: "x"}, actor: map[string]any{consts.ClaimSubject: "bob", consts.ClaimExpirationTime: 2}},
		{name: "ShouldAcceptMapClaims", mayAct: jwt.MapClaims{consts.ClaimSubject: "bob"}, actor: map[string]any{consts.ClaimSubject: "bob"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &ActorTokenValidationHandler{}

			req := newActorValidationRequest(t, newConfidentialClient(), map[string]any{
				consts.ClaimSubject:         "alice",
				consts.ClaimAuthorizedActor: tc.mayAct,
			}, tc.actor)

			err := h.HandleTokenEndpointRequest(context.Background(), req)

			if !tc.err {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		})
	}
}

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
