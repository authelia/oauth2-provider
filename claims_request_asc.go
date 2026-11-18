// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"authelia.com/provider/oauth2/x/errorsx"
)

// ClaimsASC is the configuration of OpenID Connect Advanced Syntax for Claims 1.0. The zero value disables it.
//
// An integrator which enables it must:
//   - set Evaluator, for example asc.NewEvaluator() from handler/openid/asc;
//   - call openid.EvaluateUserInfoClaims when building the UserInfo response, otherwise the rules and Transformed
//     Claims of the 'userinfo' delivery are not applied;
//   - persist Request.Claims in storage, including '_asc' and the nested claim requests;
//   - keep the session claims and source claims to what the End-User consented to release, as an abort or an omission
//     reveals information (ASC Section 7.4 and 8.7);
//   - check ClaimsRequest.HasSelectiveAbortOmit before filtering released claims with ClaimRequest.Matches (ASC
//     Section 7.2.1).
//
// The metadata of the enabled components is published by NewOpenIDConnectProviderMetadata.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html
type ClaimsASC struct {
	// SelectiveAbortOmit enables the Selective Abort/Omit rules of the '_asc/sao' member.
	SelectiveAbortOmit bool

	// TransformedClaims enables Transformed Claims.
	TransformedClaims bool

	// DisableCustomTransformedClaims rejects a request which defines Transformed Claims, leaving only the predefined
	// ones. It corresponds to a 'transformed_claims_max_count' metadata value of 0.
	DisableCustomTransformedClaims bool

	// AllowUnprotectedSelectiveAbortOmit accepts Selective Abort/Omit rules from a request which is neither pushed
	// by an authenticated client nor sent in a signed request object. A client implementing
	// SelectiveAbortOmitIntegrityClient overrides this value.
	//
	// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-9.1
	AllowUnprotectedSelectiveAbortOmit bool

	// TransformedClaimsMaxDepth is the maximum number of functions in a Transformed Claim definition. Defaults to
	// DefaultTransformedClaimsMaxDepth. A negative value removes the limit.
	//
	// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-9.2
	TransformedClaimsMaxDepth int

	// TransformedClaimsMaxCount is the maximum number of Transformed Claims a request can define. Defaults to
	// DefaultTransformedClaimsMaxCount. A negative value removes the limit.
	//
	// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-9.2
	TransformedClaimsMaxCount int

	// Evaluator validates the transformation functions and evaluates the request. It is required when either
	// component is enabled.
	Evaluator ClaimsASCEvaluator
}

// ClaimsASCEvaluator evaluates the Advanced Syntax for Claims. The handler/openid/asc package implements it.
type ClaimsASCEvaluator interface {
	// ValidateTransformedClaimFunction returns an error when the function is not supported, or its arguments are
	// wrong in number or type.
	ValidateTransformedClaimFunction(name string, args []any) (err error)

	// SupportsSchema returns true if the Selective Abort/Omit method 'schema' is supported.
	SupportsSchema() (supported bool)

	// FunctionNames returns the names of the supported transformation functions, which is the value of the
	// 'transformed_claims_functions_supported' metadata.
	FunctionNames() (names []string)

	// PredefinedTransformedClaims returns the Predefined Transformed Claims by name, which is the value of the
	// 'transformed_claims_predefined' metadata.
	PredefinedTransformedClaims() (definitions map[string]*TransformedClaim)

	// Evaluate returns the claims of the delivery type with the Transformed Claims added and the Selective Abort/Omit
	// rules applied. The sources are claims a Transformed Claim may be based on which are not released, and the
	// protected names are top level claims which are never omitted.
	Evaluate(ctx context.Context, request *ClaimsRequest, delivery string, claims, sources map[string]any, protected []string) (result map[string]any, err error)
}

// GetClaimsASC returns the configuration from config when it implements ClaimsASCProvider, with the default maximum
// depth and count applied to those which are zero. A negative maximum is no limit.
func GetClaimsASC(ctx context.Context, config any) (asc ClaimsASC) {
	if provider, ok := config.(ClaimsASCProvider); ok {
		asc = provider.GetClaimsASC(ctx)
	}

	if asc.TransformedClaimsMaxDepth == 0 {
		asc.TransformedClaimsMaxDepth = DefaultTransformedClaimsMaxDepth
	}

	if asc.TransformedClaimsMaxCount == 0 {
		asc.TransformedClaimsMaxCount = DefaultTransformedClaimsMaxCount
	}

	return asc
}

// ClaimsRequestASC is the '_asc' member of the OpenID Connect 1.0 'claims' request parameter. A nil member was absent
// from the request, or belongs to a component which is not enabled.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
type ClaimsRequestASC struct {
	SAO               *SelectiveAbortOmit          `json:"sao,omitzero"`
	TransformedClaims map[string]*TransformedClaim `json:"transformed_claims,omitzero"`
}

// Clone returns a deep copy of the '_asc' member.
func (a *ClaimsRequestASC) Clone() *ClaimsRequestASC {
	if a == nil {
		return nil
	}

	clone := &ClaimsRequestASC{}

	if a.SAO != nil {
		clone.SAO = &SelectiveAbortOmit{
			IDToken:  cloneSelectiveAbortOmitRules(a.SAO.IDToken),
			UserInfo: cloneSelectiveAbortOmitRules(a.SAO.UserInfo),
		}
	}

	if a.TransformedClaims != nil {
		clone.TransformedClaims = make(map[string]*TransformedClaim, len(a.TransformedClaims))

		for name, definition := range a.TransformedClaims {
			clone.TransformedClaims[name] = definition.clone()
		}
	}

	return clone
}

// SelectiveAbortOmit holds the Selective Abort/Omit rules of each delivery type, in the order they are executed.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
type SelectiveAbortOmit struct {
	IDToken  []SelectiveAbortOmitRule `json:"id_token,omitzero"`
	UserInfo []SelectiveAbortOmitRule `json:"userinfo,omitzero"`
}

// SelectiveAbortOmitRule is a Selective Abort/Omit rule. An empty Method is the default of 'exists'.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
type SelectiveAbortOmitRule struct {
	Loc    string          `json:"loc"`
	Method string          `json:"method,omitempty"`
	Schema json.RawMessage `json:"schema,omitempty"`
	Value  any             `json:"value,omitempty"`
	Values []any           `json:"values,omitempty"`
	Else   string          `json:"else"`
	What   []string        `json:"what,omitempty"`
}

// TransformedClaim is the definition of a Transformed Claim.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.2
type TransformedClaim struct {
	Claim string                     `json:"claim"`
	Fn    []TransformedClaimFunction `json:"fn"`
}

func (c *TransformedClaim) clone() *TransformedClaim {
	if c == nil {
		return nil
	}

	clone := &TransformedClaim{Claim: c.Claim}

	if c.Fn != nil {
		clone.Fn = make([]TransformedClaimFunction, len(c.Fn))

		for i, fn := range c.Fn {
			clone.Fn[i] = TransformedClaimFunction{Name: fn.Name, Args: cloneClaimValues(fn.Args)}
		}
	}

	return clone
}

// TransformedClaimFunction is the application of a transformation function. It is encoded as the function name, or
// as an array of the function name followed by its arguments.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.2
type TransformedClaimFunction struct {
	Name string
	Args []any
}

// MarshalJSON encodes a function without arguments as a string, and any other as an array.
func (f TransformedClaimFunction) MarshalJSON() (data []byte, err error) {
	if len(f.Args) == 0 {
		return json.Marshal(f.Name)
	}

	return json.Marshal(append([]any{f.Name}, f.Args...))
}

// UnmarshalJSON decodes the string and array forms.
func (f *TransformedClaimFunction) UnmarshalJSON(data []byte) (err error) {
	trimmed := bytes.TrimSpace(data)

	if len(trimmed) != 0 && trimmed[0] == '"' {
		*f = TransformedClaimFunction{}

		return json.Unmarshal(trimmed, &f.Name)
	}

	var parts []any

	if err = json.Unmarshal(trimmed, &parts); err != nil {
		return err
	}

	if len(parts) == 0 {
		return errors.New("a transformation function must be a string or a non-empty array")
	}

	name, ok := parts[0].(string)
	if !ok {
		return errors.New("the first element of a transformation function must be a string")
	}

	*f = TransformedClaimFunction{Name: name}

	if len(parts) > 1 {
		f.Args = parts[1:]
	}

	return nil
}

// HasSelectiveAbortOmit reports whether the request carries Selective Abort/Omit rules which were accepted. The
// 'value' and 'values' restrictions of the individual claim requests are ignored when it does. It reflects the request
// as parsed, so for a stored request it does not account for the component having been disabled since.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2.1
func (c *ClaimsRequest) HasSelectiveAbortOmit() bool {
	return c != nil && c.ASC != nil && c.ASC.SAO != nil
}

func cloneSelectiveAbortOmitRules(rules []SelectiveAbortOmitRule) []SelectiveAbortOmitRule {
	if rules == nil {
		return nil
	}

	clone := make([]SelectiveAbortOmitRule, len(rules))

	for i, rule := range rules {
		clone[i] = SelectiveAbortOmitRule{
			Loc:    rule.Loc,
			Method: rule.Method,
			Schema: bytes.Clone(rule.Schema),
			Value:  cloneClaimValue(rule.Value),
			Values: cloneClaimValues(rule.Values),
			Else:   rule.Else,
		}

		if rule.What != nil {
			clone[i].What = append([]string{}, rule.What...)
		}
	}

	return clone
}

func cloneClaimValues(values []any) []any {
	if values == nil {
		return nil
	}

	clone := make([]any, len(values))

	for i, value := range values {
		clone[i] = cloneClaimValue(value)
	}

	return clone
}

func parseClaimsRequestASC(config ClaimsASC, raw json.RawMessage) (asc *ClaimsRequestASC, err error) {
	if raw == nil {
		return nil, nil
	}

	members, ok := decodeClaimsASCObject(raw)
	if !ok {
		return nil, errClaimsASC(claimsRequestMemberASC, "must be a JSON object.")
	}

	asc = &ClaimsRequestASC{}

	if sao, ok := members[claimsRequestASCMemberSAO]; ok && config.SelectiveAbortOmit {
		if config.Evaluator == nil {
			return nil, errClaimsASCEvaluator()
		}

		if asc.SAO, err = parseSelectiveAbortOmit(config, sao); err != nil {
			return nil, err
		}
	}

	if definitions, ok := members[claimsRequestASCMemberTransformedClaims]; ok && config.TransformedClaims {
		if config.Evaluator == nil {
			return nil, errClaimsASCEvaluator()
		}

		if asc.TransformedClaims, err = parseTransformedClaims(config, definitions); err != nil {
			return nil, err
		}
	}

	if asc.SAO == nil && len(asc.TransformedClaims) == 0 {
		return nil, nil
	}

	return asc, nil
}

func parseSelectiveAbortOmit(config ClaimsASC, raw json.RawMessage) (sao *SelectiveAbortOmit, err error) {
	location := claimsRequestMemberASC + "/" + claimsRequestASCMemberSAO

	members, ok := decodeClaimsASCObject(raw)
	if !ok {
		return nil, errClaimsASC(location, "must be a JSON object.")
	}

	sao = &SelectiveAbortOmit{}

	if sao.IDToken, err = parseSelectiveAbortOmitRules(config, members, location, claimsRequestMemberIDToken); err != nil {
		return nil, err
	}

	if sao.UserInfo, err = parseSelectiveAbortOmitRules(config, members, location, claimsRequestMemberUserInfo); err != nil {
		return nil, err
	}

	return sao, nil
}

func parseSelectiveAbortOmitRules(config ClaimsASC, members map[string]json.RawMessage, location, delivery string) (rules []SelectiveAbortOmitRule, err error) {
	raw, ok := members[delivery]
	if !ok {
		return nil, nil
	}

	location += "/" + delivery

	var items []json.RawMessage

	if err = json.Unmarshal(raw, &items); err != nil || items == nil {
		return nil, errClaimsASC(location, "must be an array.")
	}

	rules = make([]SelectiveAbortOmitRule, len(items))

	for i, item := range items {
		if rules[i], err = parseSelectiveAbortOmitRule(config, item, fmt.Sprintf("%s/%d", location, i)); err != nil {
			return nil, err
		}
	}

	return rules, nil
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
//
//nolint:gocyclo
func parseSelectiveAbortOmitRule(config ClaimsASC, raw json.RawMessage, location string) (rule SelectiveAbortOmitRule, err error) {
	members, ok := decodeClaimsASCObject(raw)
	if !ok {
		return rule, errClaimsASC(location, "must be a JSON object.")
	}

	if !decodeClaimsASCString(members, selectiveAbortOmitRuleMemberLoc, &rule.Loc) {
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberLoc, "is required and must be a string.")
	}

	if !isJSONPointer(rule.Loc) {
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberLoc, "must be a JSON Pointer.")
	}

	method := SelectiveAbortOmitMethodExists

	if _, ok = members[selectiveAbortOmitRuleMemberMethod]; ok {
		if !decodeClaimsASCString(members, selectiveAbortOmitRuleMemberMethod, &rule.Method) {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberMethod, "must be one of 'exists', 'simple' or 'schema'.")
		}

		method = rule.Method
	}

	switch method {
	case SelectiveAbortOmitMethodExists, SelectiveAbortOmitMethodSimple, SelectiveAbortOmitMethodSchema:
	default:
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberMethod, "must be one of 'exists', 'simple' or 'schema'.")
	}

	schema, hasSchema := members[selectiveAbortOmitRuleMemberSchema]

	switch {
	case method == SelectiveAbortOmitMethodSchema && !hasSchema:
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberSchema, "is required when the method is 'schema'.")
	case method != SelectiveAbortOmitMethodSchema && hasSchema:
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberSchema, "must not be present unless the method is 'schema'.")
	case hasSchema:
		if _, ok = decodeClaimsASCObject(schema); !ok {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberSchema, "must be a JSON object.")
		}

		// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.3
		if !config.Evaluator.SupportsSchema() {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberMethod, "has the value 'schema' which is not supported.")
		}

		rule.Schema = bytes.Clone(schema)
	}

	value, hasValue := members[selectiveAbortOmitRuleMemberValue]
	values, hasValues := members[selectiveAbortOmitRuleMemberValues]

	switch {
	case method != SelectiveAbortOmitMethodSimple && (hasValue || hasValues):
		return rule, errClaimsASC(location, "must not have 'value' or 'values' unless the method is 'simple'.")
	case method != SelectiveAbortOmitMethodSimple:
	case hasValue == hasValues:
		return rule, errClaimsASC(location, "must have exactly one of 'value' and 'values' when the method is 'simple'.")
	case hasValue:
		if err = json.Unmarshal(value, &rule.Value); err != nil || !isClaimScalar(rule.Value) {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberValue, "must be a string, number or boolean.")
		}
	default:
		if err = json.Unmarshal(values, &rule.Values); err != nil || len(rule.Values) == 0 {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberValues, "must be a non-empty array of strings, numbers or booleans.")
		}

		for _, item := range rule.Values {
			if !isClaimScalar(item) {
				return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberValues, "must be a non-empty array of strings, numbers or booleans.")
			}
		}
	}

	if !decodeClaimsASCString(members, selectiveAbortOmitRuleMemberElse, &rule.Else) || (rule.Else != SelectiveAbortOmitActionAbort && rule.Else != SelectiveAbortOmitActionOmit) {
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberElse, "must be 'abort' or 'omit'.")
	}

	what, hasWhat := members[selectiveAbortOmitRuleMemberWhat]

	switch {
	case hasWhat && rule.Else != SelectiveAbortOmitActionOmit:
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberWhat, "must not be present unless the action is 'omit'.")
	case hasWhat:
		if err = json.Unmarshal(what, &rule.What); err != nil || len(rule.What) == 0 {
			return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberWhat, "must be a non-empty array of JSON Pointers.")
		}

		for _, pointer := range rule.What {
			if pointer == "" || !isJSONPointer(pointer) {
				return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberWhat, "must be a non-empty array of JSON Pointers.")
			}
		}
	case rule.Else == SelectiveAbortOmitActionOmit && rule.Loc == "":
		return rule, errClaimsASC(location+"/"+selectiveAbortOmitRuleMemberWhat, "is required when 'loc' is the whole document.")
	}

	return rule, nil
}

type transformedClaimDefinition struct {
	Claim json.RawMessage   `json:"claim"`
	Fn    []json.RawMessage `json:"fn"`
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.7
func parseTransformedClaims(config ClaimsASC, raw json.RawMessage) (definitions map[string]*TransformedClaim, err error) {
	location := claimsRequestMemberASC + "/" + claimsRequestASCMemberTransformedClaims

	members, ok := decodeClaimsASCObject(raw)
	if !ok {
		return nil, errClaimsASC(location, "must be a JSON object.")
	}

	if len(members) == 0 {
		return nil, nil
	}

	if config.DisableCustomTransformedClaims {
		return nil, errClaimsASC(location, "must not define transformed claims as only predefined transformed claims are supported.")
	}

	if config.TransformedClaimsMaxCount >= 0 && len(members) > config.TransformedClaimsMaxCount {
		return nil, errClaimsASC(location, fmt.Sprintf("must not define more than %d transformed claims.", config.TransformedClaimsMaxCount))
	}

	names, decoded, err := decodeTransformedClaimDefinitions(location, members)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		if config.TransformedClaimsMaxDepth >= 0 && len(decoded[name].Fn) > config.TransformedClaimsMaxDepth {
			return nil, errClaimsASC(location+"/"+name+"/fn", fmt.Sprintf("must not apply more than %d functions.", config.TransformedClaimsMaxDepth))
		}
	}

	definitions = make(map[string]*TransformedClaim, len(names))

	for _, name := range names {
		if definitions[name], err = buildTransformedClaim(config, location+"/"+name, decoded[name]); err != nil {
			return nil, err
		}
	}

	return definitions, nil
}

func decodeTransformedClaimDefinitions(location string, members map[string]json.RawMessage) (names []string, decoded map[string]transformedClaimDefinition, err error) {
	names = make([]string, 0, len(members))

	for name := range members {
		names = append(names, name)
	}

	sort.Strings(names)

	decoded = make(map[string]transformedClaimDefinition, len(members))

	for _, name := range names {
		// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.5
		if name == "" || name[0] == ':' {
			return nil, nil, errClaimsASC(location, "must not define a transformed claim with a name which is empty or starts with a colon.")
		}

		var d transformedClaimDefinition

		if _, ok := decodeClaimsASCObject(members[name]); !ok || json.Unmarshal(members[name], &d) != nil {
			return nil, nil, errClaimsASC(location+"/"+name, "must be a JSON object with a 'claim' string and an 'fn' array.")
		}

		decoded[name] = d
	}

	return names, decoded, nil
}

func buildTransformedClaim(config ClaimsASC, location string, d transformedClaimDefinition) (claim *TransformedClaim, err error) {
	claim = &TransformedClaim{Fn: make([]TransformedClaimFunction, len(d.Fn))}

	if d.Claim == nil || json.Unmarshal(d.Claim, &claim.Claim) != nil || claim.Claim == "" {
		return nil, errClaimsASC(location+"/claim", "is required and must be a string.")
	}

	if len(d.Fn) == 0 {
		return nil, errClaimsASC(location+"/fn", "must be a non-empty array.")
	}

	for i, fn := range d.Fn {
		if err = buildTransformedClaimFunction(config, fmt.Sprintf("%s/fn/%d", location, i), fn, &claim.Fn[i]); err != nil {
			return nil, err
		}
	}

	return claim, nil
}

func buildTransformedClaimFunction(config ClaimsASC, location string, raw json.RawMessage, fn *TransformedClaimFunction) (err error) {
	if json.Unmarshal(raw, fn) != nil || fn.Name == "" {
		return errClaimsASC(location, "must be a function name or an array which starts with one.")
	}

	if err = config.Evaluator.ValidateTransformedClaimFunction(fn.Name, fn.Args); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter member '%s' uses the function '%s' which is not supported or has arguments which are not valid: %s.", location, fn.Name, err.Error()).WithWrap(err).WithDebugError(err))
	}

	return nil
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-9.1
func validateClaimsRequestIntegrity(ctx context.Context, config any, client Client, claims *ClaimsRequest, protected bool) (err error) {
	if protected || claims == nil || claims.ASC == nil {
		return nil
	}

	if len(claims.ASC.TransformedClaims) != 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter defines transformed claims, which requires a pushed authorization request or a signed request object."))
	}

	if sao := claims.ASC.SAO; sao != nil && len(sao.IDToken)+len(sao.UserInfo) != 0 && !allowUnprotectedSelectiveAbortOmit(ctx, config, client) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter has selective abort and omit rules, which requires a pushed authorization request or a signed request object."))
	}

	return nil
}

func allowUnprotectedSelectiveAbortOmit(ctx context.Context, config any, client Client) bool {
	if c, ok := client.(SelectiveAbortOmitIntegrityClient); ok {
		return c.GetAllowUnprotectedSelectiveAbortOmit()
	}

	return GetClaimsASC(ctx, config).AllowUnprotectedSelectiveAbortOmit
}

func decodeClaimsASCObject(raw json.RawMessage) (members map[string]json.RawMessage, ok bool) {
	trimmed := bytes.TrimSpace(raw)

	if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &members) != nil {
		return nil, false
	}

	return members, true
}

func decodeClaimsASCString(members map[string]json.RawMessage, name string, value *string) (ok bool) {
	raw, ok := members[name]
	if !ok {
		return false
	}

	trimmed := bytes.TrimSpace(raw)

	return len(trimmed) != 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, value) == nil
}

func isClaimScalar(value any) bool {
	switch value.(type) {
	case string, float64, bool:
		return true
	default:
		return false
	}
}

// See: https://www.rfc-editor.org/rfc/rfc6901#section-3
func isJSONPointer(pointer string) bool {
	if pointer == "" {
		return true
	}

	if pointer[0] != '/' {
		return false
	}

	for i := strings.IndexByte(pointer, '~'); i != -1; {
		if i+1 >= len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1') {
			return false
		}

		next := strings.IndexByte(pointer[i+1:], '~')
		if next == -1 {
			break
		}

		i += 1 + next
	}

	return true
}

func errClaimsASC(location, reason string) error {
	return errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter member '%s' %s", location, reason))
}

func errClaimsASCEvaluator() error {
	return errorsx.WithStack(ErrServerError.WithDebug("The Advanced Syntax for Claims is enabled but the 'ClaimsASC' configuration has no 'Evaluator'."))
}

const (
	// SelectiveAbortOmitMethodExists is the Selective Abort/Omit method which performs no match.
	SelectiveAbortOmitMethodExists = "exists"

	// SelectiveAbortOmitMethodSimple is the Selective Abort/Omit method which matches 'value' or 'values'.
	SelectiveAbortOmitMethodSimple = "simple"

	// SelectiveAbortOmitMethodSchema is the Selective Abort/Omit method which applies a JSON Schema.
	SelectiveAbortOmitMethodSchema = "schema"

	// SelectiveAbortOmitActionAbort is the Selective Abort/Omit action which aborts the transaction.
	SelectiveAbortOmitActionAbort = "abort"

	// SelectiveAbortOmitActionOmit is the Selective Abort/Omit action which omits elements from the response.
	SelectiveAbortOmitActionOmit = "omit"

	// DefaultTransformedClaimsMaxDepth is the default maximum number of functions in a Transformed Claim definition.
	DefaultTransformedClaimsMaxDepth = 8

	// DefaultTransformedClaimsMaxCount is the default maximum number of Transformed Claims a request can define.
	DefaultTransformedClaimsMaxCount = 16
)

const (
	claimsRequestMemberASC = "_asc"

	claimsRequestASCMemberSAO               = "sao"
	claimsRequestASCMemberTransformedClaims = "transformed_claims"

	selectiveAbortOmitRuleMemberLoc    = "loc"
	selectiveAbortOmitRuleMemberMethod = "method"
	selectiveAbortOmitRuleMemberSchema = "schema"
	selectiveAbortOmitRuleMemberValue  = "value"
	selectiveAbortOmitRuleMemberValues = "values"
	selectiveAbortOmitRuleMemberElse   = "else"
	selectiveAbortOmitRuleMemberWhat   = "what"
)
