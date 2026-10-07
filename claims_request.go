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

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

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
// GetClaimsParameterMaxLength allows.
func ParseRequestedClaims(ctx context.Context, config any, form url.Values) (claims *ClaimsRequest, err error) {
	maximum := GetClaimsParameterMaxLength(ctx, config)

	for _, value := range form[consts.FormParameterClaims] {
		if len(value) > maximum {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'claims' parameter must not be longer than %d bytes.", maximum))
		}
	}

	return ParseClaimsRequest(form)
}

// ParseClaimsRequest parses the 'claims' request parameter. It returns nil when the parameter is absent or empty.
// Members which are not understood are ignored.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
func ParseClaimsRequest(form url.Values) (claims *ClaimsRequest, err error) {
	values := form[consts.FormParameterClaims]

	switch {
	case len(values) > 1:
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must not be included more than once."))
	case len(values) == 0, values[0] == "":
		return nil, nil
	}

	var members map[string]json.RawMessage

	if err = json.Unmarshal([]byte(values[0]), &members); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must be a JSON object.").WithWrap(err).WithDebugError(err))
	}

	if members == nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'claims' parameter must be a JSON object."))
	}

	claims = &ClaimsRequest{}

	if claims.IDToken, err = parseClaimsRequestMember(members, claimsRequestMemberIDToken); err != nil {
		return nil, err
	}

	if claims.UserInfo, err = parseClaimsRequestMember(members, claimsRequestMemberUserInfo); err != nil {
		return nil, err
	}

	return claims, nil
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
}


// Clone returns a deep copy of the claims request.
func (c *ClaimsRequest) Clone() *ClaimsRequest {
	if c == nil {
		return nil
	}

	return &ClaimsRequest{
		IDToken:  cloneClaimRequests(c.IDToken),
		UserInfo: cloneClaimRequests(c.UserInfo),
	}
}

// ClaimRequest is an individual claim request. A nil ClaimRequest is the JSON null, which requests a Voluntary Claim
// in the default manner.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
type ClaimRequest struct {
	Essential bool  `json:"essential,omitempty"`
	Value     any   `json:"value,omitempty"`
	Values    []any `json:"values,omitempty"`
}

// UnmarshalJSON decodes the 'essential', 'value' and 'values' members, matching member names exactly. Other members are
// ignored.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
func (r *ClaimRequest) UnmarshalJSON(data []byte) (err error) {
	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return err
	}

	*r = ClaimRequest{}

	if raw, ok := members[claimRequestMemberEssential]; ok && !isJSONNull(raw) {
		if err = json.Unmarshal(raw, &r.Essential); err != nil {
			return err
		}
	}

	if raw, ok := members[claimRequestMemberValue]; ok && !isJSONNull(raw) {
		if err = json.Unmarshal(raw, &r.Value); err != nil {
			return err
		}
	}

	if raw, ok := members[claimRequestMemberValues]; ok && !isJSONNull(raw) {
		if err = json.Unmarshal(raw, &r.Values); err != nil {
			return err
		}
	}

	return nil
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
	if r, ok := claimNumber(requested); ok {
		a, ok := claimNumber(actual)

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

		c := &ClaimRequest{Essential: request.Essential, Value: cloneClaimValue(request.Value)}

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

func claimNumber(value any) (number float64, ok bool) {
	switch n := value.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()

		return f, err == nil
	default:
		return 0, false
	}
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

const (
	claimsRequestMemberIDToken  = "id_token"
	claimsRequestMemberUserInfo = "userinfo"

	claimRequestMemberEssential = "essential"
	claimRequestMemberValue     = "value"
	claimRequestMemberValues    = "values"
)