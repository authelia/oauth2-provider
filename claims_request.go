// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"reflect"

	"authelia.com/provider/oauth2/internal/claimvalue"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const jsonNull = "null"

// GetClaimsParameterMaxLength returns the maximum from config when it implements ClaimsParameterMaxLengthProvider
// with a positive value, and the default of 8192 otherwise.
func GetClaimsParameterMaxLength(ctx context.Context, config any) int {
	if provider, ok := config.(ClaimsParameterMaxLengthProvider); ok {
		if maximum := provider.GetClaimsParameterMaxLength(ctx); maximum > 0 {
			return maximum
		}
	}

	return defaultClaimsParameterMaxLength
}

// ParseRequestedClaims parses the 'claims' request parameter after rejecting a value longer than
// GetClaimsParameterMaxLength allows. The '_asc' member and the nested claim requests are parsed and validated for the
// components GetClaimsASC enables.
func ParseRequestedClaims(ctx context.Context, config any, form url.Values) (claims *ClaimsRequest, err error) {
	maximum := GetClaimsParameterMaxLength(ctx, config)

	for _, value := range form[consts.FormParameterClaims] {
		if len(value) > maximum {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter must not be longer than %d bytes.", maximum))
		}
	}

	var raw json.RawMessage

	if claims, raw, err = parseClaimsRequest(form); err != nil || claims == nil {
		return nil, err
	}

	asc := GetClaimsASC(ctx, config)

	if !asc.SelectiveAbortOmit && !asc.TransformedClaims {
		stripClaimRequestMembers(claims.IDToken)
		stripClaimRequestMembers(claims.UserInfo)

		return claims, nil
	}

	if claims.ASC, err = parseClaimsRequestASC(asc, raw); err != nil {
		return nil, err
	}

	return claims, nil
}

// ParseClaimsRequest parses the 'claims' request parameter. It returns nil when the parameter is absent or empty.
// Members which are not understood are ignored.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
func ParseClaimsRequest(form url.Values) (claims *ClaimsRequest, err error) {
	if claims, _, err = parseClaimsRequest(form); err != nil || claims == nil {
		return nil, err
	}

	stripClaimRequestMembers(claims.IDToken)
	stripClaimRequestMembers(claims.UserInfo)

	return claims, nil
}

func parseClaimsRequest(form url.Values) (claims *ClaimsRequest, asc json.RawMessage, err error) {
	values := form[consts.FormParameterClaims]

	switch {
	case len(values) > 1:
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must not be included more than once."))
	case len(values) == 0, values[0] == "":
		return nil, nil, nil
	}

	var members map[string]json.RawMessage

	if err = json.Unmarshal([]byte(values[0]), &members); err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must be a JSON object.").WithWrap(err).WithDebugError(err))
	}

	if members == nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must be a JSON object."))
	}

	claims = &ClaimsRequest{}

	if claims.IDToken, err = parseClaimsRequestMember(members, claimsRequestMemberIDToken); err != nil {
		return nil, nil, err
	}

	if claims.UserInfo, err = parseClaimsRequestMember(members, claimsRequestMemberUserInfo); err != nil {
		return nil, nil, err
	}

	return claims, members[claimsRequestMemberASC], nil
}

func stripClaimRequestMembers(requests map[string]*ClaimRequest) {
	for _, request := range requests {
		if request != nil {
			request.Members = nil
		}
	}
}

func parseClaimsRequestMember(members map[string]json.RawMessage, name string) (requests map[string]*ClaimRequest, err error) {
	raw, ok := members[name]
	if !ok {
		return nil, nil
	}

	if err = json.Unmarshal(raw, &requests); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter member '%s' is malformed.", name).WithWrap(err).WithDebugError(err))
	}

	if requests == nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter member '%s' is malformed.", name))
	}

	return requests, nil
}

// ClaimsRequest is the value of the OpenID Connect 1.0 'claims' request parameter. A nil member was absent from the
// request, and an empty member was present without any individual claim requests.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
type ClaimsRequest struct {
	IDToken  map[string]*ClaimRequest `json:"id_token,omitzero"`
	UserInfo map[string]*ClaimRequest `json:"userinfo,omitzero"`
	ASC      *ClaimsRequestASC        `json:"_asc,omitzero"`
}

// Clone returns a deep copy of the claims request.
func (c *ClaimsRequest) Clone() *ClaimsRequest {
	if c == nil {
		return nil
	}

	return &ClaimsRequest{
		IDToken:  cloneClaimRequests(c.IDToken),
		UserInfo: cloneClaimRequests(c.UserInfo),
		ASC:      c.ASC.Clone(),
	}
}

// ClaimRequest is an individual claim request. A nil ClaimRequest is the JSON null, which requests a Voluntary Claim
// in the default manner. Members holds the nested claim requests, which are the members other than 'essential', 'value'
// and 'values' whose value is null or a JSON object.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
type ClaimRequest struct {
	Essential bool                     `json:"essential,omitempty"`
	Value     any                      `json:"value,omitempty"`
	Values    []any                    `json:"values,omitempty"`
	Members   map[string]*ClaimRequest `json:"-"`
}

// MarshalJSON encodes the nested claim requests as members beside 'essential', 'value' and 'values'.
func (r ClaimRequest) MarshalJSON() (data []byte, err error) {
	members := make(map[string]any, len(r.Members)+3)

	for name, member := range r.Members {
		members[name] = member
	}

	if r.Essential {
		members[claimRequestMemberEssential] = true
	}

	if r.Value != nil {
		members[claimRequestMemberValue] = r.Value
	}

	if len(r.Values) != 0 {
		members[claimRequestMemberValues] = r.Values
	}

	return json.Marshal(members)
}

// UnmarshalJSON decodes the 'essential', 'value' and 'values' members, matching member names exactly, and the nested
// claim requests to a depth of 8 below this claim request. Other members, nested members which are malformed, and
// nested members below that depth are ignored.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
func (r *ClaimRequest) UnmarshalJSON(data []byte) (err error) {
	return r.decode(data, 0)
}

func (r *ClaimRequest) decode(data []byte, depth int) (err error) {
	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return err
	}

	*r = ClaimRequest{}

	for name, raw := range members {
		if err = r.decodeMember(name, raw, depth); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClaimRequest) decodeMember(name string, raw json.RawMessage, depth int) (err error) {
	switch name {
	case claimRequestMemberEssential:
		return decodeClaimRequestMember(raw, &r.Essential)
	case claimRequestMemberValue:
		return decodeClaimRequestMember(raw, &r.Value)
	case claimRequestMemberValues:
		return decodeClaimRequestMember(raw, &r.Values)
	default:
		r.decodeNested(name, raw, depth)

		return nil
	}
}

func (r *ClaimRequest) decodeNested(name string, raw json.RawMessage, depth int) {
	if depth >= claimRequestMaxDepth {
		return
	}

	var member *ClaimRequest

	switch trimmed := bytes.TrimSpace(raw); {
	case isJSONNull(raw):
	case len(trimmed) != 0 && trimmed[0] == '{':
		member = &ClaimRequest{}

		if member.decode(raw, depth+1) != nil {
			return
		}
	default:
		return
	}

	if r.Members == nil {
		r.Members = map[string]*ClaimRequest{}
	}

	r.Members[name] = member
}

func decodeClaimRequestMember(raw json.RawMessage, target any) (err error) {
	if isJSONNull(raw) {
		return nil
	}

	return json.Unmarshal(raw, target)
}

// HasValues reports whether the claim was requested with a 'value' or 'values' member.
func (r *ClaimRequest) HasValues() bool {
	return r != nil && (r.Value != nil || len(r.Values) != 0)
}

// Matches reports whether the claim value satisfies the request. A request without a 'value' or 'values' member is
// satisfied by any value.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
func (r *ClaimRequest) Matches(value any) bool {
	if !r.HasValues() {
		return true
	}

	if r.Value != nil && claimValuesEqual(r.Value, value) {
		return true
	}

	for _, requested := range r.Values {
		if claimValuesEqual(requested, value) {
			return true
		}
	}

	return false
}

func claimValuesEqual(requested, actual any) bool {
	if r, ok := claimvalue.Number[float64](requested); ok {
		a, ok := claimvalue.Number[float64](actual)

		return ok && r == a
	}

	return reflect.DeepEqual(requested, actual)
}

func cloneClaimRequests(requests map[string]*ClaimRequest) map[string]*ClaimRequest {
	if requests == nil {
		return nil
	}

	clone := make(map[string]*ClaimRequest, len(requests))

	for name, request := range requests {
		if request == nil {
			clone[name] = nil

			continue
		}

		c := &ClaimRequest{Essential: request.Essential, Value: cloneClaimValue(request.Value), Members: cloneClaimRequests(request.Members)}

		if request.Values != nil {
			c.Values = make([]any, len(request.Values))

			for i, value := range request.Values {
				c.Values[i] = cloneClaimValue(value)
			}
		}

		clone[name] = c
	}

	return clone
}

func cloneClaimValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		clone := make(map[string]any, len(v))

		for key, item := range v {
			clone[key] = cloneClaimValue(item)
		}

		return clone
	case []any:
		clone := make([]any, len(v))

		for i, item := range v {
			clone[i] = cloneClaimValue(item)
		}

		return clone
	default:
		return value
	}
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == jsonNull
}

const (
	claimsRequestMemberIDToken  = "id_token"
	claimsRequestMemberUserInfo = "userinfo"

	claimRequestMemberEssential = "essential"
	claimRequestMemberValue     = "value"
	claimRequestMemberValues    = "values"

	claimRequestMaxDepth = 8
)
