// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	policyMemberMaxRegistrations = "max_registrations"
	policyMemberJWKS             = "jwks"
	policyMemberScope            = "scope"

	policyDefaultSigningAlg        = "RS256"
	policyDefaultContentEncryption = "A128CBC-HS256"

	policyRulePattern  = "pattern"
	policyRuleOneOf    = "one_of"
	policyRuleSubsetOf = "subset_of"
)

var (
	policyStandardMembers = policyReflectStandardMembers()
	policyMemberFields    = policyReflectMemberFields()
	policyOmittedMembers  = policyOmissions()
)

type policyOmission func(metadata *oauth2.ClientRegistrationMetadata) (values []string, required bool)

type policyRule struct {
	kind    string
	pattern string
	re      *regexp.Regexp
	values  []string
}

// RegistrationPolicy is a parsed registration policy claim: per member rules and an optional registration counter
// ceiling that constrain the client metadata a client creation token may register.
type RegistrationPolicy struct {
	rules            map[string]policyRule
	custom           map[string]struct{}
	maxRegistrations int64
}

// ParseRegistrationPolicy parses the raw registration policy claim of a client creation token. The claim must be a
// JSON object whose members are 'max_registrations', a client metadata member or a name in custom, each non counter
// member holding exactly one of the 'pattern', 'one_of' and 'subset_of' rules. A 'pattern' rule is rejected unless
// patterns is true. Errors wrap oauth2.ErrInvalidClientMetadata.
func ParseRegistrationPolicy(claim any, custom []string, patterns bool) (policy *RegistrationPolicy, err error) {
	var raw []byte

	if raw, err = json.Marshal(claim); err != nil {
		return nil, policyError("The registration policy must be a JSON object.")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var value any

	if err = decoder.Decode(&value); err != nil {
		return nil, policyError("The registration policy must be a JSON object.")
	}

	root, ok := value.(map[string]any)
	if !ok {
		return nil, policyError("The registration policy must be a JSON object.")
	}

	policy = &RegistrationPolicy{
		rules:  make(map[string]policyRule, len(root)),
		custom: make(map[string]struct{}, len(custom)),
	}

	for _, name := range custom {
		if !slices.Contains(policyStandardMembers, name) {
			policy.custom[name] = struct{}{}
		}
	}

	for _, member := range sortedKeys(root) {
		if member == policyMemberMaxRegistrations {
			if policy.maxRegistrations, err = parsePolicyMaxRegistrations(root[member]); err != nil {
				return nil, err
			}

			continue
		}

		if _, isCustom := policy.custom[member]; !isCustom && !slices.Contains(policyStandardMembers, member) {
			return nil, policyErrorf("The registration policy member '%s' is not a known client metadata member.", member)
		}

		if member == policyMemberJWKS {
			return nil, policyErrorf("The registration policy member '%s' cannot be constrained.", member)
		}

		var rule policyRule

		if rule, err = parsePolicyRule(member, root[member]); err != nil {
			return nil, err
		}

		if rule.kind == policyRulePattern && !patterns {
			return nil, policyErrorf("The registration policy member '%s' rule '%s' is not permitted from the issuer of the presented Client Registration Token.", member, policyRulePattern)
		}

		policy.rules[member] = rule
	}

	return policy, nil
}

// MaxRegistrations returns the 'max_registrations' ceiling of the policy, or 0 when it is unset.
func (p *RegistrationPolicy) MaxRegistrations() (max int64) {
	return p.maxRegistrations
}

// Check evaluates the client metadata against every rule of the policy using the value the registered client will
// effectively have. An omitted member with a default defined by RFC 7591 Section 2, OpenID Connect Dynamic Client
// Registration 1.0 Section 2 or the stored client's getters is checked as that default; an omitted member whose
// effective value the server or the client's keys would choose, or whose absence permits any value, must be sent; any
// other omitted member has no values. A 'pattern' rule requires every value to match, 'subset_of' every value to be
// listed and 'one_of' exactly one value that is listed. Each language tagged variant of a member (RFC 7591 Section 2.2,
// OpenID Connect Dynamic Client Registration 1.0 Section 2.1) present in the metadata is checked against the member's
// rule on its own. Errors wrap oauth2.ErrInvalidClientMetadata, or oauth2.ErrInvalidRedirectURI for 'redirect_uris'
// per RFC 7591 Section 3.2.2.
func (p *RegistrationPolicy) Check(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	members := make([]string, 0, len(p.rules))

	for member := range p.rules {
		members = append(members, member)
	}

	slices.Sort(members)

	for _, member := range members {
		rule := p.rules[member]

		values, supported := p.policyValues(member, metadata)
		if !supported {
			return policyErrorf("The '%s' value is not a type the registration policy can evaluate.", member)
		}

		if omitted, ok := policyOmittedMembers[member]; ok && len(values) == 0 {
			var required bool

			if values, required = omitted(metadata); required {
				return policyErrorf("The '%s' value is required by the registration policy.", member)
			}
		}

		if err = rule.check(member, values); err != nil {
			return err
		}

		for _, tagged := range policyTaggedMembers(member, metadata.Extra) {
			if values, supported = policyCustomValues(metadata.Extra[tagged]); !supported {
				return policyErrorf("The '%s' value is not a type the registration policy can evaluate.", tagged)
			}

			if err = rule.check(tagged, values); err != nil {
				return err
			}
		}
	}

	return nil
}

func policyBaseMember(member string) (base string) {
	base, _, _ = strings.Cut(member, "#")

	return base
}

// policyTaggedMembers returns the sorted names in extra of the language tagged variants of member.
func policyTaggedMembers(member string, extra map[string]any) (names []string) {
	for name := range extra {
		if base, tag, ok := strings.Cut(name, "#"); ok && base == member && tag != "" {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

func (r policyRule) check(member string, values []string) (err error) {
	if err = r.checkValues(member, values); err != nil && policyBaseMember(member) == consts.ClientMetadataRedirectURIs {
		return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHint(oauth2.ErrorToRFC6749Error(err).HintField))
	}

	return err
}

func (r policyRule) checkValues(member string, values []string) (err error) {
	switch r.kind {
	case policyRulePattern:
		for _, value := range values {
			if !r.re.MatchString(value) {
				return policyErrorf("The '%s' value '%s' is not permitted by the registration policy.", member, value)
			}
		}
	case policyRuleSubsetOf:
		for _, value := range values {
			if !slices.Contains(r.values, value) {
				return policyErrorf("The '%s' value '%s' is not permitted by the registration policy.", member, value)
			}
		}
	case policyRuleOneOf:
		if len(values) != 1 {
			return policyErrorf("The '%s' value must be exactly one of the values permitted by the registration policy.", member)
		}

		if !slices.Contains(r.values, values[0]) {
			return policyErrorf("The '%s' value '%s' is not permitted by the registration policy.", member, values[0])
		}
	}

	return nil
}

func (p *RegistrationPolicy) policyValues(member string, metadata *oauth2.ClientRegistrationMetadata) (values []string, ok bool) {
	if p.isCustom(member) {
		return policyCustomValues(metadata.Extra[member])
	}

	index, found := policyMemberFields[member]
	if !found {
		return nil, true
	}

	field := reflect.ValueOf(metadata).Elem().Field(index)

	switch field.Kind() {
	case reflect.String:
		if field.String() == "" {
			return nil, true
		}

		if member == policyMemberScope {
			return strings.Fields(field.String()), true
		}

		return []string{field.String()}, true
	case reflect.Slice:
		values = make([]string, field.Len())

		for i := range values {
			values[i] = field.Index(i).String()
		}

		return values, true
	case reflect.Bool:
		return []string{strconv.FormatBool(field.Bool())}, true
	case reflect.Pointer:
		if field.IsNil() {
			return nil, true
		}

		if field.Elem().Kind() == reflect.Int64 {
			return []string{strconv.FormatInt(field.Elem().Int(), 10)}, true
		}
	}

	return nil, false
}

func policyCustomValues(value any) (values []string, ok bool) {
	switch v := value.(type) {
	case nil:
		return nil, true
	case string:
		return []string{v}, true
	case bool:
		return []string{strconv.FormatBool(v)}, true
	case json.Number:
		return []string{v.String()}, true
	case []any:
		values = make([]string, len(v))

		for i, item := range v {
			s, isString := item.(string)
			if !isString {
				return nil, false
			}

			values[i] = s
		}

		return values, true
	}

	return nil, false
}

func (p *RegistrationPolicy) isCustom(member string) (ok bool) {
	_, ok = p.custom[member]

	return ok
}

// WithoutMaxRegistrations returns the normalized policy claim without 'max_registrations', which only applies to
// client creation and so is not copied onto a client management token.
func (p *RegistrationPolicy) WithoutMaxRegistrations() (claim map[string]any) {
	claim = make(map[string]any, len(p.rules))

	for member, rule := range p.rules {
		if rule.kind == policyRulePattern {
			claim[member] = map[string]any{rule.kind: rule.pattern}

			continue
		}

		values := make([]any, len(rule.values))

		for i, v := range rule.values {
			values[i] = v
		}

		claim[member] = map[string]any{rule.kind: values}
	}

	return claim
}

func parsePolicyMaxRegistrations(value any) (max int64, err error) {
	number, ok := value.(json.Number)
	if ok {
		max, err = strconv.ParseInt(number.String(), 10, 64)
	}

	if !ok || err != nil || max < 1 {
		return 0, policyErrorf("The registration policy member '%s' must be a positive integer.", policyMemberMaxRegistrations)
	}

	return max, nil
}

func parsePolicyRule(member string, value any) (rule policyRule, err error) {
	object, ok := value.(map[string]any)
	if !ok {
		return rule, policyErrorf("The registration policy member '%s' must hold exactly one of '%s', '%s' or '%s'.", member, policyRulePattern, policyRuleOneOf, policyRuleSubsetOf)
	}

	keys := sortedKeys(object)

	for _, key := range keys {
		switch key {
		case policyRulePattern, policyRuleOneOf, policyRuleSubsetOf:
		default:
			return rule, policyErrorf("The registration policy member '%s' has the unknown rule '%s'.", member, key)
		}
	}

	if len(keys) != 1 {
		return rule, policyErrorf("The registration policy member '%s' must hold exactly one of '%s', '%s' or '%s'.", member, policyRulePattern, policyRuleOneOf, policyRuleSubsetOf)
	}

	rule.kind = keys[0]

	if rule.kind == policyRulePattern {
		pattern, isString := object[rule.kind].(string)
		if !isString {
			return rule, policyErrorf("The registration policy member '%s' rule '%s' must be a string.", member, rule.kind)
		}

		if rule.re, err = regexp.Compile("^(?:" + pattern + ")$"); err != nil {
			return rule, policyErrorf("The registration policy member '%s' rule '%s' is not a valid regular expression.", member, rule.kind)
		}

		rule.pattern = pattern

		return rule, nil
	}

	items, isArray := object[rule.kind].([]any)
	if !isArray {
		return rule, policyErrorf("The registration policy member '%s' rule '%s' must be an array of strings.", member, rule.kind)
	}

	rule.values = make([]string, len(items))

	for i, item := range items {
		s, isString := item.(string)
		if !isString {
			return rule, policyErrorf("The registration policy member '%s' rule '%s' must be an array of strings.", member, rule.kind)
		}

		rule.values[i] = s
	}

	return rule, nil
}

func sortedKeys(m map[string]any) (keys []string) {
	keys = make([]string, 0, len(m))

	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

func policyReflectStandardMembers() (members []string) {
	t := reflect.TypeOf(oauth2.ClientRegistrationMetadata{})

	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")

		if name == "" || name == "-" {
			continue
		}

		members = append(members, name)
	}

	return members
}

func policyReflectMemberFields() (fields map[string]int) {
	t := reflect.TypeOf(oauth2.ClientRegistrationMetadata{})

	fields = make(map[string]int, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")

		if name == "" || name == "-" {
			continue
		}

		fields[name] = i
	}

	return fields
}

func policyOmissions() (omissions map[string]policyOmission) {
	omissions = map[string]policyOmission{
		"grant_types":                             policyOmittedDefault(consts.GrantTypeAuthorizationCode),
		"response_types":                          policyOmittedDefault(consts.ResponseTypeAuthorizationCodeFlow),
		"token_endpoint_auth_method":              policyOmittedDefault(consts.ClientAuthMethodClientSecretBasic),
		"application_type":                        policyOmittedDefault("web"),
		"id_token_signed_response_alg":            policyOmittedDefault(policyDefaultSigningAlg),
		"access_token_signed_response_alg":        policyOmittedDefault(policyDefaultSigningAlg),
		"introspection_endpoint_auth_method":      policyOmittedEndpointAuthMethod,
		"revocation_endpoint_auth_method":         policyOmittedEndpointAuthMethod,
		"subject_type":                            policyOmittedRequired,
		"jwks_uri":                                policyOmittedRequired,
		"request_object_signing_alg":              policyOmittedRequired,
		"request_object_signing_kid":              policyOmittedRequired,
		"request_object_encryption_alg":           policyOmittedRequired,
		"request_object_encryption_enc":           policyOmittedRequired,
		"request_object_encryption_kid":           policyOmittedRequired,
		"token_endpoint_auth_signing_alg":         policyOmittedRequired,
		"introspection_endpoint_auth_signing_alg": policyOmittedRequired,
		"revocation_endpoint_auth_signing_alg":    policyOmittedRequired,
		"authorization_signed_response_alg":       policyOmittedRequired,
		"authorization_signed_response_kid":       policyOmittedRequired,
		"id_token_signed_response_kid":            policyOmittedRequired,
		"access_token_signed_response_kid":        policyOmittedRequired,
		"introspection_signed_response_alg":       policyOmittedRequiredWhenSet("introspection_signed_response_kid"),
		"introspection_signed_response_kid":       policyOmittedRequiredWhenAlg("introspection_signed_response_alg"),
		"userinfo_signed_response_kid":            policyOmittedRequiredWhenAlg("userinfo_signed_response_alg"),
		"token_exchange_subject_token_types":      policyOmittedRequired,
		"token_exchange_actor_token_types":        policyOmittedRequired,
		"token_exchange_request_token_types":      policyOmittedRequired,
		"token_exchange_permitted_client_ids":     policyOmittedRequired,
		"authorization_details_types":             policyOmittedAuthorizationDetailsTypes,
	}

	for _, prefix := range []string{"id_token", "userinfo", "authorization", "introspection", "access_token"} {
		alg, enc, kid := prefix+"_encrypted_response_alg", prefix+"_encrypted_response_enc", prefix+"_encrypted_response_kid"

		omissions[alg] = policyOmittedRequiredWhenSet(kid)
		omissions[kid] = policyOmittedRequiredWhenAlg(alg)
		omissions[enc] = policyOmittedEncryptedResponseEnc(alg, kid)
	}

	return omissions
}

func policyOmittedDefault(values ...string) policyOmission {
	return func(_ *oauth2.ClientRegistrationMetadata) ([]string, bool) {
		return values, false
	}
}

func policyOmittedRequired(_ *oauth2.ClientRegistrationMetadata) (values []string, required bool) {
	return nil, true
}

func policyOmittedRequiredWhenSet(member string) policyOmission {
	return func(metadata *oauth2.ClientRegistrationMetadata) ([]string, bool) {
		return nil, policyMemberString(metadata, member) != ""
	}
}

func policyOmittedRequiredWhenAlg(member string) policyOmission {
	return func(metadata *oauth2.ClientRegistrationMetadata) ([]string, bool) {
		return nil, !policyIsNoneAlg(policyMemberString(metadata, member))
	}
}

func policyOmittedEndpointAuthMethod(metadata *oauth2.ClientRegistrationMetadata) (values []string, required bool) {
	if metadata.TokenEndpointAuthMethod == "" {
		return []string{consts.ClientAuthMethodClientSecretBasic}, false
	}

	return []string{metadata.TokenEndpointAuthMethod}, false
}

func policyOmittedEncryptedResponseEnc(alg, kid string) policyOmission {
	return func(metadata *oauth2.ClientRegistrationMetadata) ([]string, bool) {
		if policyMemberString(metadata, kid) == "" && policyIsNoneAlg(policyMemberString(metadata, alg)) {
			return nil, false
		}

		return []string{policyDefaultContentEncryption}, false
	}
}

func policyOmittedAuthorizationDetailsTypes(metadata *oauth2.ClientRegistrationMetadata) (values []string, required bool) {
	return nil, metadata.AuthorizationDetailsTypes == nil
}

func policyMemberString(metadata *oauth2.ClientRegistrationMetadata, member string) (value string) {
	return reflect.ValueOf(metadata).Elem().Field(policyMemberFields[member]).String()
}

func policyIsNoneAlg(alg string) (none bool) {
	return alg == "" || alg == consts.JSONWebTokenAlgNone
}

func policyError(hint string) error {
	return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint(hint))
}

func policyErrorf(hint string, args ...any) error {
	return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf(hint, args...))
}
