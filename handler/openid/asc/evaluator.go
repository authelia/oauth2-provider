// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
)

const (
	// DeliveryIDToken is the delivery type of the claims of an ID Token.
	DeliveryIDToken = "id_token"

	// DeliveryUserInfo is the delivery type of the claims of a UserInfo response.
	DeliveryUserInfo = "userinfo"
)

const functionGet = "get"

// DefaultMatchTimeout is the default time limit of the regular expression operation of the 'match' function.
const DefaultMatchTimeout = 10 * time.Millisecond

// SchemaValidator applies a JSON Schema for the Selective Abort/Omit method 'schema'. It must not resolve a remote
// reference, as the schema is supplied by the client.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
type SchemaValidator interface {
	// ValidateSchema returns an error when the schema does not apply to the value.
	ValidateSchema(ctx context.Context, schema json.RawMessage, value any) (err error)
}

// AbortError is returned by Evaluate, as a pointer, when a rule with the 'abort' action was not fulfilled.
type AbortError struct {
	Delivery string
	Rule     int
}

// Error implements the error interface.
func (e *AbortError) Error() string {
	return fmt.Sprintf("selective abort/omit rule %d of the '%s' delivery was not fulfilled", e.Rule, e.Delivery)
}

// Evaluator evaluates the Transformed Claims and the Selective Abort/Omit rules of a claims request. It implements
// oauth2.ClaimsASCEvaluator.
type Evaluator struct {
	// Functions are the supported transformation functions by name. A function which is not standardized uses the
	// 'x-' prefix.
	Functions map[string]Function

	// Predefined are the Predefined Transformed Claims, which a request refers to with the '::' prefix. Every function
	// of a definition must be one of Functions with arguments it accepts, otherwise the claim is unavailable.
	Predefined map[string]*oauth2.TransformedClaim

	// SchemaValidator enables the Selective Abort/Omit method 'schema'.
	SchemaValidator SchemaValidator

	// MatchTimeout is the time limit of the regular expression operation of the 'match' function, after which the
	// Transformed Claim is unavailable. Defaults to DefaultMatchTimeout. A negative value removes the limit, which
	// leaves the linear time matching of the regexp package as the only bound.
	//
	// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.7
	MatchTimeout time.Duration

	// Clock returns the current time. Defaults to [time.Now].
	Clock func() time.Time
}

// NewEvaluator returns an Evaluator with the transformation functions of the specification.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4
func NewEvaluator() *Evaluator {
	e := &Evaluator{}

	e.Functions = functions(func() time.Time {
		if e.Clock != nil {
			return e.Clock()
		}

		return time.Now()
	}, func() time.Duration {
		if e.MatchTimeout == 0 {
			return DefaultMatchTimeout
		}

		return e.MatchTimeout
	})

	return e
}

// ValidateTransformedClaimFunction returns an error when the function is not supported, or its arguments are wrong in
// number or type.
func (e *Evaluator) ValidateTransformedClaimFunction(name string, args []any) (err error) {
	function, ok := e.Functions[name]
	if !ok {
		return fmt.Errorf("the function '%s' is not supported", name)
	}

	return function.Validate(args)
}

// SupportsSchema returns true if a SchemaValidator is configured.
func (e *Evaluator) SupportsSchema() (supported bool) {
	return e.SchemaValidator != nil
}

// FunctionNames returns the sorted names of the supported functions, which is the value of the
// 'transformed_claims_functions_supported' metadata.
func (e *Evaluator) FunctionNames() (names []string) {
	return slices.Sorted(maps.Keys(e.Functions))
}

// PredefinedTransformedClaims returns Predefined, which is the value of the 'transformed_claims_predefined' metadata.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.5
func (e *Evaluator) PredefinedTransformedClaims() (definitions map[string]*oauth2.TransformedClaim) {
	return e.Predefined
}

// Evaluate returns the claims of the delivery type with the requested Transformed Claims added and the Selective
// Abort/Omit rules applied. The claims and sources are not modified. A Transformed Claim is based on a claim of the
// same object in claims, or else in sources, and a value found only in sources is not returned, and a definition
// which only reads a member of it is unavailable. A Transformed Claim requested with a 'value' or 'values' member is
// returned only when the transformed value matches it, unless the request has Selective Abort/Omit rules, which
// replace those members. A nested request below a claim whose value is an array applies to every object of the array,
// and one below any other value which is not an object is not transformed. A claim named in protected, at any depth,
// is never omitted, and a top level one is not transformed into. A JSON Pointer addresses an array element by its
// index before any rule ran, and an omitted element does not exist for a later rule. An *AbortError is returned when
// a rule aborts the transaction.
//
// The claims and sources must hold only what the End-User consented to release, as the result reveals information
// about them.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
func (e *Evaluator) Evaluate(ctx context.Context, request *oauth2.ClaimsRequest, delivery string, claims, sources map[string]any, protected []string) (result map[string]any, err error) {
	if delivery != DeliveryIDToken && delivery != DeliveryUserInfo {
		return nil, fmt.Errorf("the delivery '%s' is not known", delivery)
	}

	requested, rules, definitions := requestOf(request, delivery)

	if len(rules) == 0 && !e.transforms(definitions, requested) {
		return maps.Clone(claims), nil
	}

	if result, err = normalize(claims); err != nil {
		return nil, err
	}

	if sources, err = normalize(sources); err != nil {
		return nil, err
	}

	// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.2.2
	e.transform(ctx, definitions, requested, result, sources, protected, !request.HasSelectiveAbortOmit())

	for i, rule := range rules {
		if e.fulfilled(ctx, rule, result) {
			continue
		}

		if rule.Else == oauth2.SelectiveAbortOmitActionAbort {
			return nil, &AbortError{Delivery: delivery, Rule: i}
		}

		targets := rule.What
		if len(targets) == 0 {
			targets = []string{rule.Loc}
		}

		for _, target := range targets {
			tokens, ok := parsePointer(target)
			if !ok || len(tokens) == 0 || slices.Contains(protected, tokens[0]) {
				continue
			}

			omit(result, tokens)
		}
	}

	return compact(result).(map[string]any), nil
}

func (e *Evaluator) transforms(definitions map[string]*oauth2.TransformedClaim, requested map[string]*oauth2.ClaimRequest) bool {
	for name, request := range requested {
		if e.definition(definitions, name) != nil {
			return true
		}

		if request != nil && e.transforms(definitions, request.Members) {
			return true
		}
	}

	return false
}

func (e *Evaluator) transform(ctx context.Context, definitions map[string]*oauth2.TransformedClaim, requested map[string]*oauth2.ClaimRequest, result, sources map[string]any, protected []string, restricted bool) {
	for _, name := range slices.Sorted(maps.Keys(requested)) {
		request := requested[name]

		if slices.Contains(protected, name) {
			continue
		}

		if definition := e.definition(definitions, name); definition != nil {
			if value, ok := e.derive(ctx, definition, result, sources); ok && (!restricted || satisfies(request, value)) {
				result[name] = clone(value)
			}

			continue
		}

		if request == nil || !e.transforms(definitions, request.Members) {
			continue
		}

		nested := func(child, childSources map[string]any) {
			e.transform(ctx, definitions, request.Members, child, childSources, nil, restricted)
		}

		if existing, present := result[name]; present {
			descend(existing, sources[name], nested)
		} else if created := create(sources[name], nested); created != nil {
			result[name] = created
		}
	}
}

func descend(existing, sources any, nested func(child, childSources map[string]any)) {
	switch node := existing.(type) {
	case map[string]any:
		childSources, _ := sources.(map[string]any)

		nested(node, childSources)
	case []any:
		items, _ := sources.([]any)

		for i, item := range node {
			child, ok := item.(map[string]any)
			if !ok {
				continue
			}

			var childSources map[string]any

			if len(items) == len(node) {
				childSources, _ = items[i].(map[string]any)
			}

			nested(child, childSources)
		}
	}
}

func create(sources any, nested func(child, childSources map[string]any)) (created any) {
	switch node := sources.(type) {
	case []any:
		children := make([]any, 0, len(node))

		for _, item := range node {
			childSources, ok := item.(map[string]any)
			if !ok {
				continue
			}

			child := map[string]any{}

			if nested(child, childSources); len(child) != 0 {
				children = append(children, child)
			}
		}

		if len(children) != 0 {
			return children
		}
	default:
		childSources, _ := sources.(map[string]any)

		child := map[string]any{}

		if nested(child, childSources); len(child) != 0 {
			return child
		}
	}

	return nil
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.2.1
func satisfies(request *oauth2.ClaimRequest, value any) bool {
	if !request.HasValues() {
		return true
	}

	if request.Value != nil && equal(request.Value, value) {
		return true
	}

	return slices.ContainsFunc(request.Values, func(candidate any) bool {
		return equal(candidate, value)
	})
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.5
func (e *Evaluator) definition(definitions map[string]*oauth2.TransformedClaim, name string) *oauth2.TransformedClaim {
	switch {
	case strings.HasPrefix(name, "::"):
		return e.Predefined[name[2:]]
	case strings.HasPrefix(name, ":"):
		return definitions[name[1:]]
	default:
		return nil
	}
}

func (e *Evaluator) derive(ctx context.Context, definition *oauth2.TransformedClaim, result, sources map[string]any) (value any, ok bool) {
	if len(definition.Fn) == 0 || strings.HasPrefix(definition.Claim, ":") {
		return nil, false
	}

	fromSources := false

	if value, ok = result[definition.Claim]; !ok {
		if value, ok = sources[definition.Claim]; !ok {
			return nil, false
		}

		fromSources = true
	}

	transformed := false

	for _, fn := range definition.Fn {
		function, ok := e.Functions[fn.Name]
		if !ok {
			return nil, false
		}

		if value, ok = function.Apply(ctx, value, fn.Args); !ok {
			return nil, false
		}

		if fn.Name != functionGet {
			transformed = true
		}
	}

	if fromSources && !transformed {
		return nil, false
	}

	return value, true
}

func (e *Evaluator) fulfilled(ctx context.Context, rule oauth2.SelectiveAbortOmitRule, result map[string]any) bool {
	tokens, ok := parsePointer(rule.Loc)
	if !ok {
		return false
	}

	value, ok := resolve(result, tokens)
	if !ok {
		return false
	}

	switch rule.Method {
	case "", oauth2.SelectiveAbortOmitMethodExists:
		return true
	case oauth2.SelectiveAbortOmitMethodSimple:
		if rule.Value != nil {
			return equal(rule.Value, value)
		}

		for _, candidate := range rule.Values {
			if equal(candidate, value) {
				return true
			}
		}

		return false
	case oauth2.SelectiveAbortOmitMethodSchema:
		return e.SchemaValidator != nil && e.SchemaValidator.ValidateSchema(ctx, rule.Schema, compact(value)) == nil
	default:
		return false
	}
}

func requestOf(request *oauth2.ClaimsRequest, delivery string) (requested map[string]*oauth2.ClaimRequest, rules []oauth2.SelectiveAbortOmitRule, definitions map[string]*oauth2.TransformedClaim) {
	if request == nil {
		return nil, nil, nil
	}

	switch delivery {
	case DeliveryUserInfo:
		requested = request.UserInfo
	case DeliveryIDToken:
		requested = request.IDToken
	}

	if request.ASC == nil {
		return requested, nil, nil
	}

	if sao := request.ASC.SAO; sao != nil {
		switch delivery {
		case DeliveryUserInfo:
			rules = sao.UserInfo
		case DeliveryIDToken:
			rules = sao.IDToken
		}
	}

	return requested, rules, request.ASC.TransformedClaims
}

func normalize(claims map[string]any) (normalized map[string]any, err error) {
	normalized = map[string]any{}

	if len(claims) == 0 {
		return normalized, nil
	}

	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err = decoder.Decode(&normalized); err != nil {
		return nil, err
	}

	return normalized, nil
}

func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))

		for key, member := range v {
			out[key] = clone(member)
		}

		return out
	case []any:
		out := make([]any, len(v))

		for i, member := range v {
			out[i] = clone(member)
		}

		return out
	default:
		return value
	}
}
