// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const (
	defaultMaxEvaluations = 256

	subjectTypeUser     = "user"
	subjectTypeClient   = "client"
	subjectTypeWorkload = "workload"

	resourceTypeAudience          = "audience"
	resourceTypeProtectedResource = "protected_resource"

	actionAuthorizationDetail = "authorization_detail"

	shortNameTokenExchange = "token_exchange"
)

var (
	grantTypeShortNames = map[string]string{
		consts.GrantTypeAuthorizationCode:  "authorization_code",
		consts.GrantTypeClientCredentials:  "client_credentials",
		consts.GrantTypeRefreshToken:       "refresh_token",
		consts.GrantTypeOAuthTokenExchange: shortNameTokenExchange,
		consts.GrantTypeOAuthDeviceCode:    "device_code",
		consts.GrantTypeOAuthJWTBearer:     "jwt_bearer",
	}

	tokenTypeShortNames = map[string]string{
		consts.TokenTypeRFC8693AccessToken:  "access_token",
		consts.TokenTypeRFC8693RefreshToken: "refresh_token",
		consts.TokenTypeRFC8693IDToken:      "id_token",
		consts.TokenTypeRFC8693IDJAG:        "id_jag",
		consts.TokenTypeRFC8693JWT:          "jwt",
		consts.TokenTypeRFC8693SAML1:        "saml1",
		consts.TokenTypeRFC8693SAML2:        "saml2",
	}

	reservedClaims = []string{
		consts.ClaimIssuer, consts.ClaimIssuedAt, consts.ClaimJWTID, consts.ClaimSubject, consts.ClaimAudience,
		consts.ClaimExpirationTime, consts.ClaimNotBefore, consts.ClaimScope, consts.ClaimClientIdentifier,
		consts.ClaimConfirmation, consts.ClaimActor, consts.ClaimAuthorizationDetails, consts.ClaimAuthorizedActor,
	}
)

// Policy implements oauth2.IssuancePolicy against an AuthZEN Policy Decision Point.
type Policy struct {
	// Evaluator conveys evaluations to the Policy Decision Point.
	Evaluator Evaluator

	// DefaultTarget is the issuance target of a request naming no audience or resource.
	DefaultTarget string

	// MaxEvaluations bounds the evaluations of a single token request. When not positive a default applies.
	MaxEvaluations int

	// GrantTypeNames adds short names for grant types the profile does not register. A request whose grant type has no
	// short name fails closed.
	GrantTypeNames map[string]string
}

type tupleKind int

const (
	tupleGate tupleKind = iota
	tupleScope
	tupleCell
)

type tuple struct {
	Evaluation

	kind     tupleKind
	token    oauth2.TokenType
	entry    int
	optional bool
}

// EvaluateIssuance implements oauth2.IssuancePolicy.
func (p *Policy) EvaluateIssuance(ctx context.Context, request *oauth2.IssuanceRequest) (decision *oauth2.IssuanceDecision, err error) {
	if p.Evaluator == nil {
		return nil, errors.New("the policy has no evaluator")
	}

	var tuples []tuple

	if tuples, err = p.tuples(request); err != nil {
		return nil, err
	}

	if len(tuples) > p.maxEvaluations() {
		return &oauth2.IssuanceDecision{Rejection: boundError(request)}, nil
	}

	evaluations := make([]Evaluation, len(tuples))

	for i, item := range tuples {
		evaluations[i] = item.Evaluation
	}

	var response *EvaluationsResponse

	if response, err = p.Evaluator.Evaluate(ctx, &EvaluationsRequest{
		Context:     evaluationContext(request),
		Evaluations: evaluations,
		Options:     Options{EvaluationsSemantic: semanticExecuteAll},
	}); err != nil {
		return nil, err
	}

	if response == nil || len(response.Evaluations) != len(tuples) {
		return nil, errors.New("the policy decision point did not respond with a decision for each evaluation")
	}

	return compose(request, tuples, response.Evaluations)
}

func (p *Policy) maxEvaluations() int {
	if p.MaxEvaluations > 0 {
		return p.MaxEvaluations
	}

	return defaultMaxEvaluations
}

func (p *Policy) grantShortName(grant string) (name string, err error) {
	var ok bool

	if name, ok = p.GrantTypeNames[grant]; ok {
		return name, nil
	}

	if name, ok = grantTypeShortNames[grant]; ok {
		return name, nil
	}

	return "", fmt.Errorf("the grant type '%s' has no short name", grant)
}

func (p *Policy) tuples(request *oauth2.IssuanceRequest) (tuples []tuple, err error) {
	var grant string

	if grant, err = p.grantShortName(request.GrantType); err != nil {
		return nil, err
	}

	subject := exchangeSubject(request)
	targets := unique(request.Resources, request.Audience)
	exchange := request.GrantType == consts.GrantTypeOAuthTokenExchange
	gateTargets := targets
	scopeTargets := targets

	// See: https://github.com/openid/authzen/blob/main/profiles/authzen-oauth/authzen-oauth-token-exchange-1_0.md
	if exchange && request.RequestedTokenType == consts.TokenTypeRFC8693IDJAG {
		gateTargets = unique(request.Audience)
		scopeTargets = unique(request.Audience, request.Resources)
	}

	if gateTargets, err = p.defaulted(gateTargets); err != nil {
		return nil, err
	}

	if scopeTargets, err = p.defaulted(scopeTargets); err != nil {
		return nil, err
	}

	if exchange {
		if tuples, err = exchangeGates(request, grant, subject, gateTargets); err != nil {
			return nil, err
		}
	} else {
		tuples = gates(request, grant, subject, gateTargets)
	}

	for _, scope := range request.Scopes {
		for _, target := range scopeTargets {
			tuples = append(tuples, tuple{kind: tupleScope, Evaluation: Evaluation{Subject: subject, Action: Action{Name: scope}, Resource: Entity{Type: resourceTypeProtectedResource, ID: target}}})
		}
	}

	cellTargets := scopeTargets

	if exchange && request.RequestedTokenType == consts.TokenTypeRFC8693IDJAG && len(request.Resources) != 0 {
		cellTargets = unique(request.Resources)
	}

	for i, entry := range request.AuthorizationDetails {
		tuples = append(tuples, cells(subject, i, entry, cellTargets)...)
	}

	return tuples, nil
}

func (p *Policy) defaulted(targets []string) ([]string, error) {
	if len(targets) != 0 {
		return targets, nil
	}

	if p.DefaultTarget == "" {
		return nil, errors.New("the request names no target and the policy has no default target")
	}

	return []string{p.DefaultTarget}, nil
}

func gates(request *oauth2.IssuanceRequest, grant string, subject Entity, targets []string) (tuples []tuple) {
	for _, token := range request.Tokens {
		if token == oauth2.IDToken {
			continue
		}

		for _, target := range targets {
			tuples = append(tuples, gate(token, string(token), grant, subject, target))
		}
	}

	// The audience of an ID Token is the client, and one is minted however many targets the request names.
	if slices.Contains(request.Tokens, oauth2.IDToken) {
		tuples = append(tuples, gate(oauth2.IDToken, string(oauth2.IDToken), grant, subject, request.ClientID))
	}

	return tuples
}

func exchangeGates(request *oauth2.IssuanceRequest, grant string, subject Entity, targets []string) (tuples []tuple, err error) {
	short, ok := tokenTypeShortNames[request.RequestedTokenType]
	if !ok {
		return nil, fmt.Errorf("the token type '%s' has no short name", request.RequestedTokenType)
	}

	token := oauth2.ExchangedToken

	if len(request.Tokens) != 0 {
		token = request.Tokens[0]
	}

	party := requestingParty(request)

	if request.RequestedTokenType == consts.TokenTypeRFC8693IDToken {
		targets = []string{request.ClientID}
	}

	for _, target := range targets {
		tuples = append(tuples, gate(token, short, grant, subject, target))

		if party != subject {
			tuples = append(tuples, gate(token, short, grant, party, target))
		}
	}

	// A refresh token minted alongside the requested token is omitted rather than failing the request when denied.
	if len(request.Tokens) > 1 {
		for _, target := range targets {
			subjectGate := gate(oauth2.RefreshToken, string(oauth2.RefreshToken), grant, subject, target)
			subjectGate.optional = true

			tuples = append(tuples, subjectGate)

			if party != subject {
				partyGate := gate(oauth2.RefreshToken, string(oauth2.RefreshToken), grant, party, target)
				partyGate.optional = true

				tuples = append(tuples, partyGate)
			}
		}
	}

	return tuples, nil
}

func gate(token oauth2.TokenType, short, grant string, subject Entity, target string) tuple {
	return tuple{
		kind:  tupleGate,
		token: token,
		Evaluation: Evaluation{
			Subject:  subject,
			Action:   Action{Name: "issue:" + short + ":" + grant},
			Resource: Entity{Type: resourceTypeAudience, ID: target},
		},
	}
}

// cells forms one evaluation per cell of the product an entry requests.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2.2
func cells(subject Entity, index int, entry oauth2.AuthorizationDetail, targets []string) (tuples []tuple) {
	locations := entry.Locations
	if len(locations) == 0 {
		locations = targets
	}

	actions := entry.Actions
	if len(actions) == 0 {
		actions = []string{actionAuthorizationDetail}
	}

	datatypes := entry.DataTypes
	if len(datatypes) == 0 {
		datatypes = []string{""}
	}

	for _, location := range locations {
		for _, action := range actions {
			for _, datatype := range datatypes {
				name := action

				if datatype != "" && !strings.Contains(datatype, ":") {
					name = action + ":" + datatype
				}

				tuples = append(tuples, tuple{
					kind:  tupleCell,
					entry: index,
					Evaluation: Evaluation{
						Subject:  subject,
						Action:   Action{Name: name},
						Resource: Entity{Type: entry.Type, ID: location},
					},
				})
			}
		}
	}

	return tuples
}

func exchangeSubject(request *oauth2.IssuanceRequest) Entity {
	if request.Subject == "" {
		return Entity{Type: subjectTypeClient, ID: request.ClientID}
	}

	return Entity{Type: subjectTypeUser, ID: request.Subject}
}

func requestingParty(request *oauth2.IssuanceRequest) Entity {
	if request.Actor != "" && request.Actor != request.ClientID {
		return Entity{Type: subjectTypeWorkload, ID: request.Actor}
	}

	return Entity{Type: subjectTypeClient, ID: request.ClientID}
}

func evaluationContext(request *oauth2.IssuanceRequest) map[string]any {
	out := map[string]any{}

	for key, value := range map[string]string{
		consts.ClaimClientIdentifier: request.ClientID,
		"subject_token_type":         request.SubjectTokenType,
		"actor_token_type":           request.ActorTokenType,
	} {
		if value != "" {
			out[key] = value
		}
	}

	if request.Act != nil {
		out[consts.ClaimActor] = request.Act
	}

	if request.MayAct != nil {
		out[consts.ClaimAuthorizedActor] = request.MayAct
	}

	return out
}

func boundError(request *oauth2.IssuanceRequest) error {
	switch {
	case len(request.AuthorizationDetails) != 0:
		return oauth2.ErrInvalidAuthorizationDetails
	case request.GrantType == consts.GrantTypeOAuthTokenExchange:
		return oauth2.ErrInvalidTarget
	default:
		return oauth2.ErrInvalidScope
	}
}

func unique(lists ...[]string) (out []string) {
	for _, list := range lists {
		for _, value := range list {
			if !slices.Contains(out, value) {
				out = append(out, value)
			}
		}
	}

	return out
}

// shaping accumulates the response context of the permitted items speaking for each token type.
type shaping struct {
	lifespans    map[oauth2.TokenType]time.Duration
	grantedScope oauth2.Arguments
	hasGranted   bool
}

//nolint:gocyclo
func compose(request *oauth2.IssuanceRequest, tuples []tuple, decisions []Decision) (decision *oauth2.IssuanceDecision, err error) {
	var (
		exchange   = request.GrantType == consts.GrantTypeOAuthTokenExchange
		shape      = &shaping{lifespans: map[oauth2.TokenType]time.Duration{}}
		deniedCell = map[int]bool{}
		deniedName = map[string]bool{}
	)

	decision = &oauth2.IssuanceDecision{}

	for i, item := range tuples {
		if decisions[i].Decision == nil {
			return nil, errors.New("the policy decision point responded with an item with no decision")
		}

		if !*decisions[i].Decision {
			switch item.kind {
			case tupleGate:
				if (exchange && !item.optional) || (!exchange && item.token == oauth2.AccessToken) {
					decision.Denied = true
				} else if !slices.Contains(decision.DeniedTokens, item.token) {
					decision.DeniedTokens = append(decision.DeniedTokens, item.token)
				}
			case tupleScope:
				deniedName[item.Action.Name] = true
			case tupleCell:
				deniedCell[item.entry] = true
			}

			continue
		}

		var denied bool

		if denied, err = shape.apply(item, decisions[i].Context); err != nil {
			return nil, err
		}

		decision.Denied = decision.Denied || denied
	}

	if decision.Denied {
		return &oauth2.IssuanceDecision{Denied: true}, nil
	}

	if len(shape.lifespans) != 0 {
		decision.Lifespans = shape.lifespans
	}

	decision.Scopes = narrowedScopes(request.Scopes, deniedName, shape)

	if len(deniedCell) != 0 {
		decision.AuthorizationDetails = oauth2.AuthorizationDetails{}

		for i, entry := range request.AuthorizationDetails {
			if !deniedCell[i] {
				decision.AuthorizationDetails = append(decision.AuthorizationDetails, entry)
			}
		}
	}

	return decision, nil
}

func narrowedScopes(requested oauth2.Arguments, denied map[string]bool, shape *shaping) oauth2.Arguments {
	if len(requested) == 0 {
		if shape.hasGranted {
			return shape.grantedScope
		}

		return nil
	}

	out := oauth2.Arguments{}

	for _, scope := range requested {
		if !denied[scope] && (!shape.hasGranted || slices.Contains(shape.grantedScope, scope)) {
			out = append(out, scope)
		}
	}

	if len(out) == len(requested) {
		return nil
	}

	return out
}

func (s *shaping) apply(item tuple, responseContext map[string]any) (denied bool, err error) {
	raw, ok := responseContext["issuance"]
	if !ok {
		return false, nil
	}

	issuance, ok := raw.(map[string]any)
	if !ok {
		return false, errors.New("the 'issuance' response context is not an object")
	}

	// Scope and authorization detail tuples speak only for the access token.
	token := item.token
	if item.kind != tupleGate {
		token = oauth2.AccessToken
	}

	for key, value := range issuance {
		var keyDenied bool

		switch key {
		case "token_lifetime":
			keyDenied, err = s.applyLifetime(token, value)
		case "granted_scope":
			if token == oauth2.AccessToken {
				err = s.applyGrantedScope(value)
			}
		case "audience":
			keyDenied, err = applyAudience(item, value)
		case "crit":
			keyDenied, err = applyCrit(value)
		case "claims":
			keyDenied, err = applyClaims(value)
		default:
			keyDenied = true
		}

		if err != nil {
			return false, err
		}

		denied = denied || keyDenied
	}

	return denied, nil
}

func (s *shaping) applyLifetime(token oauth2.TokenType, value any) (denied bool, err error) {
	seconds, ok := value.(float64)
	if !ok || seconds < 0 || seconds != math.Trunc(seconds) || seconds > math.MaxInt32 {
		return false, errors.New("the 'token_lifetime' is not a non-negative integer")
	}

	if seconds == 0 {
		return true, nil
	}

	lifespan := time.Duration(seconds) * time.Second

	if current, set := s.lifespans[token]; !set || lifespan < current {
		s.lifespans[token] = lifespan
	}

	return false, nil
}

func (s *shaping) applyGrantedScope(value any) (err error) {
	scope, ok := value.(string)
	if !ok {
		return errors.New("the 'granted_scope' is not a string")
	}

	if !s.hasGranted {
		s.grantedScope = oauth2.Arguments{}
	}

	s.hasGranted = true

	for _, name := range strings.Fields(scope) {
		if !slices.Contains(s.grantedScope, name) {
			s.grantedScope = append(s.grantedScope, name)
		}
	}

	return nil
}

func applyAudience(item tuple, value any) (denied bool, err error) {
	values, ok := value.([]any)
	if !ok {
		return false, errors.New("the 'audience' is not an array")
	}

	if len(values) == 0 {
		return true, nil
	}

	for _, target := range values {
		if target != item.Resource.ID {
			return true, nil
		}
	}

	return false, nil
}

func applyCrit(value any) (denied bool, err error) {
	values, ok := value.([]any)
	if !ok {
		return false, errors.New("the 'crit' is not an array")
	}

	return len(values) != 0, nil
}

func applyClaims(value any) (denied bool, err error) {
	claims, ok := value.(map[string]any)
	if !ok {
		return false, errors.New("the 'claims' is not an object")
	}

	for name := range claims {
		if slices.Contains(reservedClaims, name) {
			return true, nil
		}
	}

	return false, nil
}

var _ oauth2.IssuancePolicy = (*Policy)(nil)
