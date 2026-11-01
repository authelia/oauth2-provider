// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const apiTarget = "https://api.example"

func TestPolicyFormsTuples(t *testing.T) {
	testCases := []struct {
		name     string
		request  *oauth2.IssuanceRequest
		expected []string
	}{
		{
			name:     "ShouldFormGateAndScopeForClientCredentials",
			request:  &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Scopes: oauth2.Arguments{"telemetry.write"}, Audience: oauth2.Arguments{apiTarget}},
			expected: []string{"client:svc issue:access_token:client_credentials audience:" + apiTarget, "client:svc telemetry.write protected_resource:" + apiTarget},
		},
		{
			name:     "ShouldUseDefaultTargetWithoutRequestedTarget",
			request:  &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}},
			expected: []string{"client:svc issue:access_token:client_credentials audience:https://default.example"},
		},
		{
			name:    "ShouldFormEachTokenGateFirstAndIDTokenGateForTheClient",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeAuthorizationCode, ClientID: "app", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken, oauth2.RefreshToken, oauth2.IDToken}, Scopes: oauth2.Arguments{"openid"}, Audience: oauth2.Arguments{apiTarget}},
			expected: []string{
				"user:alice issue:access_token:authorization_code audience:" + apiTarget,
				"user:alice issue:refresh_token:authorization_code audience:" + apiTarget,
				"user:alice issue:id_token:authorization_code audience:app",
				"user:alice openid protected_resource:" + apiTarget,
			},
		},
		{
			name:    "ShouldFanOutAcrossTargets",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Scopes: oauth2.Arguments{"s"}, Audience: oauth2.Arguments{"https://a.example"}, Resources: oauth2.Arguments{"https://b.example", "https://a.example"}},
			expected: []string{
				"client:svc issue:access_token:client_credentials audience:https://b.example",
				"client:svc issue:access_token:client_credentials audience:https://a.example",
				"client:svc s protected_resource:https://b.example",
				"client:svc s protected_resource:https://a.example",
			},
		},
		{
			name:    "ShouldFormSubjectAndRequestingPartyGatesForTokenExchange",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, ClientID: "agent", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Scopes: oauth2.Arguments{"s"}, Audience: oauth2.Arguments{apiTarget}},
			expected: []string{
				"user:alice issue:access_token:token_exchange audience:" + apiTarget,
				"client:agent issue:access_token:token_exchange audience:" + apiTarget,
				"user:alice s protected_resource:" + apiTarget,
			},
		},
		{
			name:    "ShouldUseActorAsRequestingParty",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, ClientID: "agent", Subject: "alice", Actor: "wl-1", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget}},
			expected: []string{
				"user:alice issue:access_token:token_exchange audience:" + apiTarget,
				"workload:wl-1 issue:access_token:token_exchange audience:" + apiTarget,
			},
		},
		{
			name:     "ShouldCollapseCoincidingGates",
			request:  &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget}},
			expected: []string{"client:svc issue:access_token:token_exchange audience:" + apiTarget},
		},
		{
			name:    "ShouldEvaluateIDJAGAtTwoLevels",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693IDJAG, ClientID: "agent", Subject: "alice", Scopes: oauth2.Arguments{"s"}, Audience: oauth2.Arguments{"https://ras.example"}, Resources: oauth2.Arguments{apiTarget}},
			expected: []string{
				"user:alice issue:id_jag:token_exchange audience:https://ras.example",
				"client:agent issue:id_jag:token_exchange audience:https://ras.example",
				"user:alice s protected_resource:https://ras.example",
				"user:alice s protected_resource:" + apiTarget,
			},
		},
		{
			name:    "ShouldDecomposeAuthorizationDetailsIntoCells",
			request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget}, AuthorizationDetails: oauth2.AuthorizationDetails{{Type: "t", Locations: []string{"l1", "l2"}, Actions: []string{"read"}, DataTypes: []string{"d", "x:y"}}, {Type: "u"}}},
			expected: []string{
				"client:svc issue:access_token:client_credentials audience:" + apiTarget,
				"client:svc read:d t:l1",
				"client:svc read t:l1",
				"client:svc read:d t:l2",
				"client:svc read t:l2",
				"client:svc authorization_detail u:" + apiTarget,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := &evaluatorStub{}
			policy := &Policy{Evaluator: evaluator, DefaultTarget: "https://default.example"}

			_, err := policy.EvaluateIssuance(context.Background(), tc.request)
			require.NoError(t, err)

			actual := make([]string, 0, len(evaluator.request.Evaluations))

			for _, e := range evaluator.request.Evaluations {
				actual = append(actual, e.Subject.Type+":"+e.Subject.ID+" "+e.Action.Name+" "+e.Resource.Type+":"+e.Resource.ID)
			}

			assert.Equal(t, tc.expected, actual)
			assert.Equal(t, semanticExecuteAll, evaluator.request.Options.EvaluationsSemantic)
		})
	}
}

func TestPolicyAppliesResponses(t *testing.T) {
	request := func() *oauth2.IssuanceRequest {
		return &oauth2.IssuanceRequest{GrantType: consts.GrantTypeAuthorizationCode, ClientID: "app", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken, oauth2.RefreshToken}, Scopes: oauth2.Arguments{"a", "b"}, Audience: oauth2.Arguments{apiTarget}}
	}

	permit := Decision{Decision: boolean(true)}
	deny := Decision{Decision: boolean(false)}

	issuance := func(value map[string]any) Decision {
		return Decision{Decision: boolean(true), Context: map[string]any{"issuance": value}}
	}

	testCases := []struct {
		name      string
		decisions []Decision
		assert    func(t *testing.T, d *oauth2.IssuanceDecision)
		err       bool
	}{
		{name: "ShouldPermit", decisions: []Decision{permit, permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) {
			assert.False(t, d.Denied)
			assert.Nil(t, d.Scopes)
			assert.Empty(t, d.DeniedTokens)
		}},
		{name: "ShouldDenyOnRequiredGate", decisions: []Decision{deny, permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldOmitOptionalToken", decisions: []Decision{permit, deny, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) {
			assert.False(t, d.Denied)
			assert.Equal(t, []oauth2.TokenType{oauth2.RefreshToken}, d.DeniedTokens)
		}},
		{name: "ShouldNarrowScopes", decisions: []Decision{permit, permit, deny, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.Equal(t, oauth2.Arguments{"b"}, d.Scopes) }},
		{name: "ShouldNarrowEveryScope", decisions: []Decision{permit, permit, deny, deny}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.Equal(t, oauth2.Arguments{}, d.Scopes) }},
		{name: "ShouldApplyMinimumLifetimePerToken", decisions: []Decision{issuance(map[string]any{"token_lifetime": 300}), issuance(map[string]any{"token_lifetime": 60}), issuance(map[string]any{"token_lifetime": 100}), permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) {
			assert.Equal(t, 100*time.Second, d.Lifespans[oauth2.AccessToken])
			assert.Equal(t, 60*time.Second, d.Lifespans[oauth2.RefreshToken])
		}},
		{name: "ShouldDenyOnZeroLifetime", decisions: []Decision{issuance(map[string]any{"token_lifetime": 0}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldIgnoreShapingOnDeniedItem", decisions: []Decision{permit, permit, {Decision: boolean(false), Context: map[string]any{"issuance": map[string]any{"crit": []any{"x"}}}}, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) {
			assert.False(t, d.Denied)
			assert.Equal(t, oauth2.Arguments{"b"}, d.Scopes)
		}},
		{name: "ShouldIgnoreMembersOutsideIssuance", decisions: []Decision{{Decision: boolean(true), Context: map[string]any{"reason_admin": "secret"}}, permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.False(t, d.Denied) }},
		{name: "ShouldDropAdvisoryClaims", decisions: []Decision{issuance(map[string]any{"claims": map[string]any{"groups": []any{"x"}}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.False(t, d.Denied) }},
		{name: "ShouldDenyOnCrit", decisions: []Decision{issuance(map[string]any{"claims": map[string]any{"max": 1}, "crit": []any{"max"}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldDenyOnReservedClaim", decisions: []Decision{issuance(map[string]any{"claims": map[string]any{"act": map[string]any{"sub": "x"}}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldDenyOnUnknownIssuanceMember", decisions: []Decision{issuance(map[string]any{"future": true}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldDenyOnAuthorizationDetailsShaping", decisions: []Decision{issuance(map[string]any{"authorization_details": []any{}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldDenyOnEmptyAudience", decisions: []Decision{issuance(map[string]any{"audience": []any{}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldDenyOnForeignAudience", decisions: []Decision{issuance(map[string]any{"audience": []any{"https://other.example"}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.True(t, d.Denied) }},
		{name: "ShouldKeepMatchingAudience", decisions: []Decision{issuance(map[string]any{"audience": []any{apiTarget}}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.False(t, d.Denied) }},
		{name: "ShouldIntersectGrantedScope", decisions: []Decision{issuance(map[string]any{"granted_scope": "a"}), permit, permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.Equal(t, oauth2.Arguments{"a"}, d.Scopes) }},
		{name: "ShouldIgnoreGrantedScopeOnRefreshGate", decisions: []Decision{permit, issuance(map[string]any{"granted_scope": "a"}), permit, permit}, assert: func(t *testing.T, d *oauth2.IssuanceDecision) { assert.Nil(t, d.Scopes) }},
		{name: "ShouldErrorOnShortResponse", decisions: []Decision{permit}, err: true},
		{name: "ShouldErrorOnLongResponse", decisions: []Decision{permit, permit, permit, permit, permit}, err: true},
		{name: "ShouldErrorOnMissingDecision", decisions: []Decision{{}, permit, permit, permit}, err: true},
		{name: "ShouldErrorOnWrongShapingType", decisions: []Decision{issuance(map[string]any{"token_lifetime": "300"}), permit, permit, permit}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decisions := roundTrip(t, tc.decisions)
			policy := &Policy{Evaluator: &evaluatorStub{response: &EvaluationsResponse{Evaluations: decisions}}}

			decision, err := policy.EvaluateIssuance(context.Background(), request())

			if tc.err {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			tc.assert(t, decision)
		})
	}
}

func TestPolicyGrantedScopeWithoutScopeTuples(t *testing.T) {
	policy := &Policy{Evaluator: &evaluatorStub{response: &EvaluationsResponse{Evaluations: roundTrip(t, []Decision{{Decision: boolean(true), Context: map[string]any{"issuance": map[string]any{"granted_scope": "a b"}}}})}}}

	decision, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget}})

	require.NoError(t, err)
	assert.Equal(t, oauth2.Arguments{"a", "b"}, decision.Scopes)
}

func TestPolicyTokenExchangeGatesAreRequired(t *testing.T) {
	permit, deny := Decision{Decision: boolean(true)}, Decision{Decision: boolean(false)}

	policy := &Policy{Evaluator: &evaluatorStub{response: &EvaluationsResponse{Evaluations: []Decision{permit, deny}}}}

	decision, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693RefreshToken, ClientID: "agent", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.RefreshToken}, Audience: oauth2.Arguments{apiTarget}})

	require.NoError(t, err)
	assert.True(t, decision.Denied)
}

func TestPolicyTokenExchangeRefreshTokenGateIsOptional(t *testing.T) {
	permit, deny := Decision{Decision: boolean(true)}, Decision{Decision: boolean(false)}

	evaluator := &evaluatorStub{response: &EvaluationsResponse{Evaluations: []Decision{permit, permit, deny, permit}}}
	policy := &Policy{Evaluator: evaluator}

	decision, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, ClientID: "agent", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken, oauth2.RefreshToken}, Audience: oauth2.Arguments{apiTarget}})

	require.NoError(t, err)
	assert.False(t, decision.Denied)
	assert.Equal(t, []oauth2.TokenType{oauth2.RefreshToken}, decision.DeniedTokens)
	assert.Equal(t, "issue:refresh_token:token_exchange", evaluator.request.Evaluations[2].Action.Name)
}

func TestPolicyLifetimeOfAnExchangedTokenIsKeyedToTheOutput(t *testing.T) {
	evaluator := &evaluatorStub{response: &EvaluationsResponse{Evaluations: roundTrip(t, []Decision{{Decision: boolean(true), Context: map[string]any{"issuance": map[string]any{"token_lifetime": 60}}}, {Decision: boolean(true)}})}}
	policy := &Policy{Evaluator: evaluator}

	decision, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693IDJAG, ClientID: "agent", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.ExchangedToken}, Audience: oauth2.Arguments{apiTarget}})

	require.NoError(t, err)
	assert.Equal(t, time.Minute, decision.Lifespans[oauth2.ExchangedToken])
}

func TestPolicyDropsAuthorizationDetailWithDeniedCell(t *testing.T) {
	permit, deny := Decision{Decision: boolean(true)}, Decision{Decision: boolean(false)}
	kept := oauth2.AuthorizationDetail{Type: "kept", Locations: []string{"l"}, Actions: []string{"a"}}

	policy := &Policy{Evaluator: &evaluatorStub{response: &EvaluationsResponse{Evaluations: []Decision{permit, permit, permit, deny}}}}

	decision, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget}, AuthorizationDetails: oauth2.AuthorizationDetails{kept, {Type: "dropped", Locations: []string{"l"}, Actions: []string{"a", "b"}}}})

	require.NoError(t, err)
	assert.Equal(t, oauth2.AuthorizationDetails{kept}, decision.AuthorizationDetails)
}

func TestPolicyBoundsTheBatch(t *testing.T) {
	testCases := []struct {
		name     string
		request  *oauth2.IssuanceRequest
		expected error
	}{
		{name: "ShouldReportScope", request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Scopes: oauth2.Arguments{"a", "b", "c"}}, expected: oauth2.ErrInvalidScope},
		{name: "ShouldReportTargetOnTokenExchange", request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, ClientID: "agent", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken}, Scopes: oauth2.Arguments{"a", "b"}}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldReportAuthorizationDetails", request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}, AuthorizationDetails: oauth2.AuthorizationDetails{{Type: "t", Actions: []string{"a", "b", "c"}}}}, expected: oauth2.ErrInvalidAuthorizationDetails},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := &evaluatorStub{}
			policy := &Policy{Evaluator: evaluator, DefaultTarget: apiTarget, MaxEvaluations: 3}

			decision, err := policy.EvaluateIssuance(context.Background(), tc.request)

			require.NoError(t, err)
			assert.ErrorIs(t, decision.Rejection, tc.expected)
			assert.Nil(t, evaluator.request)
		})
	}
}

func TestPolicyFailsClosedOnConfiguration(t *testing.T) {
	testCases := []struct {
		name    string
		policy  *Policy
		request *oauth2.IssuanceRequest
	}{
		{name: "ShouldErrorWithoutTarget", policy: &Policy{Evaluator: &evaluatorStub{}}, request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}}},
		{name: "ShouldErrorOnUnregisteredGrant", policy: &Policy{Evaluator: &evaluatorStub{}, DefaultTarget: apiTarget}, request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeResourceOwnerPasswordCredentials, ClientID: "svc", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken}}},
		{name: "ShouldErrorOnUnregisteredTokenType", policy: &Policy{Evaluator: &evaluatorStub{}, DefaultTarget: apiTarget}, request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: "urn:example:custom", ClientID: "svc"}},
		{name: "ShouldErrorOnEvaluatorError", policy: &Policy{Evaluator: &evaluatorStub{err: errors.New("down")}, DefaultTarget: apiTarget}, request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}}},
		{name: "ShouldErrorWithoutEvaluator", policy: &Policy{DefaultTarget: apiTarget}, request: &oauth2.IssuanceRequest{GrantType: consts.GrantTypeClientCredentials, ClientID: "svc", Tokens: []oauth2.TokenType{oauth2.AccessToken}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.policy.EvaluateIssuance(context.Background(), tc.request)

			assert.Error(t, err)
		})
	}
}

func TestPolicyGrantTypeNames(t *testing.T) {
	evaluator := &evaluatorStub{}
	policy := &Policy{Evaluator: evaluator, DefaultTarget: apiTarget, GrantTypeNames: map[string]string{consts.GrantTypeResourceOwnerPasswordCredentials: "password"}}

	_, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{GrantType: consts.GrantTypeResourceOwnerPasswordCredentials, ClientID: "svc", Subject: "alice", Tokens: []oauth2.TokenType{oauth2.AccessToken}})

	require.NoError(t, err)
	assert.Equal(t, "issue:access_token:password", evaluator.request.Evaluations[0].Action.Name)
}

func TestPolicyConveysDelegationContext(t *testing.T) {
	evaluator := &evaluatorStub{}
	policy := &Policy{Evaluator: evaluator}

	_, err := policy.EvaluateIssuance(context.Background(), &oauth2.IssuanceRequest{
		GrantType: consts.GrantTypeOAuthTokenExchange, RequestedTokenType: consts.TokenTypeRFC8693AccessToken, SubjectTokenType: consts.TokenTypeRFC8693AccessToken, ActorTokenType: consts.TokenTypeRFC8693JWT,
		ClientID: "agent", Subject: "alice", Actor: "wl", Act: map[string]any{"sub": "prior"}, MayAct: map[string]any{"sub": "wl"},
		Tokens: []oauth2.TokenType{oauth2.AccessToken}, Audience: oauth2.Arguments{apiTarget},
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"client_id": "agent", "subject_token_type": consts.TokenTypeRFC8693AccessToken, "actor_token_type": consts.TokenTypeRFC8693JWT,
		"act": map[string]any{"sub": "prior"}, "may_act": map[string]any{"sub": "wl"},
	}, evaluator.request.Context)
}

func TestHTTPEvaluator(t *testing.T) {
	var (
		body  map[string]any
		token string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = r.Header.Get(consts.HeaderAuthorization)

		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)

		w.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
		_, _ = w.Write([]byte(`{"evaluations":[{"decision":true}]}`))
	}))
	defer server.Close()

	evaluator := &HTTPEvaluator{Endpoint: server.URL, Authorize: func(_ context.Context, r *http.Request) error {
		r.Header.Set(consts.HeaderAuthorization, "Bearer pdp")

		return nil
	}}

	response, err := evaluator.Evaluate(context.Background(), &EvaluationsRequest{Evaluations: []Evaluation{{Subject: Entity{Type: "client", ID: "svc"}, Action: Action{Name: "a"}, Resource: Entity{Type: "audience", ID: "r"}}}, Options: Options{EvaluationsSemantic: semanticExecuteAll}})

	require.NoError(t, err)
	require.Len(t, response.Evaluations, 1)
	assert.True(t, *response.Evaluations[0].Decision)
	assert.Equal(t, "Bearer pdp", token)
	assert.Equal(t, map[string]any{"evaluations_semantic": "execute_all"}, body["options"])
}

func TestHTTPEvaluatorFailures(t *testing.T) {
	testCases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "ShouldErrorOnStatus", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }},
		{name: "ShouldErrorOnMalformedBody", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{`)) }},
		{name: "ShouldNotFollowRedirect", handler: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/moved" {
				_, _ = w.Write([]byte(`{"evaluations":[{"decision":true}]}`))

				return
			}

			http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			_, err := (&HTTPEvaluator{Endpoint: server.URL}).Evaluate(context.Background(), &EvaluationsRequest{})

			assert.Error(t, err)
		})
	}
}

type evaluatorStub struct {
	request  *EvaluationsRequest
	response *EvaluationsResponse
	err      error
}

func (s *evaluatorStub) Evaluate(_ context.Context, request *EvaluationsRequest) (*EvaluationsResponse, error) {
	s.request = request

	if s.err != nil {
		return nil, s.err
	}

	if s.response != nil {
		return s.response, nil
	}

	response := &EvaluationsResponse{}

	for range request.Evaluations {
		response.Evaluations = append(response.Evaluations, Decision{Decision: boolean(true)})
	}

	return response, nil
}

func boolean(value bool) *bool {
	return &value
}

func roundTrip(t *testing.T, decisions []Decision) (out []Decision) {
	t.Helper()

	data, err := json.Marshal(EvaluationsResponse{Evaluations: decisions})
	require.NoError(t, err)

	var response EvaluationsResponse

	require.NoError(t, json.Unmarshal(data, &response))

	return response.Evaluations
}
