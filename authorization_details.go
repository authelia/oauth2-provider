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
	"maps"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	authorizationDetailMemberType       = "type"
	authorizationDetailMemberLocations  = "locations"
	authorizationDetailMemberActions    = "actions"
	authorizationDetailMemberDataTypes  = "datatypes"
	authorizationDetailMemberIdentifier = "identifier"
	authorizationDetailMemberPrivileges = "privileges"
)

// AuthorizationDetail is a single RFC 9396 authorization details object. The common data fields are typed; every
// other member is kept in Extra so type-specific and enriched members round-trip unchanged. Numbers in Extra decode
// as json.Number. A nil slice or Identifier is an absent member and a non-nil empty one is present, so an empty
// member is issued exactly as it was validated and granted.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
type AuthorizationDetail struct {
	Type       string
	Locations  []string
	Actions    []string
	DataTypes  []string
	Identifier *string
	Privileges []string
	Extra      map[string]any
}

// AuthorizationDetails is the RFC 9396 'authorization_details' array.
type AuthorizationDetails []AuthorizationDetail

// MarshalJSON encodes the detail as a single JSON object. The common fields take precedence over an Extra member of
// the same name.
func (d AuthorizationDetail) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(d.Extra)+6)

	for key, value := range d.Extra {
		if !isAuthorizationDetailCommonMember(key) {
			m[key] = value
		}
	}

	m[authorizationDetailMemberType] = d.Type

	if d.Locations != nil {
		m[authorizationDetailMemberLocations] = d.Locations
	}

	if d.Actions != nil {
		m[authorizationDetailMemberActions] = d.Actions
	}

	if d.DataTypes != nil {
		m[authorizationDetailMemberDataTypes] = d.DataTypes
	}

	if d.Identifier != nil {
		m[authorizationDetailMemberIdentifier] = *d.Identifier
	}

	if d.Privileges != nil {
		m[authorizationDetailMemberPrivileges] = d.Privileges
	}

	return json.Marshal(m)
}

// UnmarshalJSON decodes a JSON object, rejecting common fields of the wrong JSON type, including null members and
// null array elements.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2.2
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func (d *AuthorizationDetail) UnmarshalJSON(data []byte) (err error) {
	var raw map[string]json.RawMessage

	if err = json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw == nil {
		return fmt.Errorf("authorization detail is not a JSON object")
	}

	*d = AuthorizationDetail{}

	for key, value := range raw {
		if isAuthorizationDetailCommonMember(key) && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return &authorizationDetailNullMemberError{member: key}
		}

		switch key {
		case authorizationDetailMemberType:
			err = json.Unmarshal(value, &d.Type)
		case authorizationDetailMemberLocations:
			d.Locations, err = decodeAuthorizationDetailStrings(key, value)
		case authorizationDetailMemberActions:
			d.Actions, err = decodeAuthorizationDetailStrings(key, value)
		case authorizationDetailMemberDataTypes:
			d.DataTypes, err = decodeAuthorizationDetailStrings(key, value)
		case authorizationDetailMemberIdentifier:
			err = json.Unmarshal(value, &d.Identifier)
		case authorizationDetailMemberPrivileges:
			d.Privileges, err = decodeAuthorizationDetailStrings(key, value)
		default:
			var decoded any

			if decoded, err = decodeAuthorizationDetailValue(value); err == nil {
				if d.Extra == nil {
					d.Extra = map[string]any{}
				}

				d.Extra[key] = decoded
			}
		}

		if err != nil {
			return fmt.Errorf("authorization detail member '%s' is invalid: %w", key, err)
		}
	}

	return nil
}

// Clone returns a deep copy of the detail. Extra is normalised through JSON: numbers become json.Number and structs
// become maps.
func (d AuthorizationDetail) Clone() AuthorizationDetail {
	c := d

	c.Locations = slices.Clone(d.Locations)
	c.Actions = slices.Clone(d.Actions)
	c.DataTypes = slices.Clone(d.DataTypes)
	c.Privileges = slices.Clone(d.Privileges)

	if d.Identifier != nil {
		c.Identifier = new(*d.Identifier)
	}

	c.Extra = cloneAuthorizationDetailExtra(d.Extra)

	return c
}

// Clone returns a deep copy of the details, or nil when d is nil.
func (d AuthorizationDetails) Clone() AuthorizationDetails {
	if d == nil {
		return nil
	}

	c := make(AuthorizationDetails, len(d))

	for i, detail := range d {
		c[i] = detail.Clone()
	}

	return c
}

// ParseAuthorizationDetails parses the 'authorization_details' parameter value. An empty value is absent and returns
// nil. Anything other than a non-empty JSON array of objects that each have a non-empty string 'type' is rejected
// with ErrInvalidAuthorizationDetails.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func ParseAuthorizationDetails(raw string) (details AuthorizationDetails, err error) {
	if raw == "" {
		return nil, nil
	}

	var elements []json.RawMessage

	if err = json.Unmarshal([]byte(raw), &elements); err != nil {
		return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("The 'authorization_details' parameter must be a JSON array.").WithWrap(err).WithDebugError(err))
	}

	if elements == nil {
		return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("The 'authorization_details' parameter must be a JSON array."))
	}

	if len(elements) == 0 {
		return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("The 'authorization_details' parameter must contain at least one authorization details object."))
	}

	details = make(AuthorizationDetails, len(elements))

	for i, element := range elements {
		if trimmed := bytes.TrimSpace(element); len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter element at index %d must be a JSON object.", i))
		}

		if err = json.Unmarshal(element, &details[i]); err != nil {
			var null *authorizationDetailNullMemberError

			if errors.As(err, &null) {
				if null.element {
					return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter element at index %d member '%s' must not contain null.", i, null.member).WithWrap(err).WithDebugError(err))
				}

				return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter element at index %d member '%s' must not be null.", i, null.member).WithWrap(err).WithDebugError(err))
			}

			return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter element at index %d is malformed.", i).WithWrap(err).WithDebugError(err))
		}

		if details[i].Type == "" {
			return nil, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter element at index %d must have a non-empty 'type'.", i))
		}
	}

	return details, nil
}

type authorizationDetailNullMemberError struct {
	member  string
	element bool
}

func (e *authorizationDetailNullMemberError) Error() string {
	if e.element {
		return fmt.Sprintf("authorization detail member '%s' must not contain null", e.member)
	}

	return fmt.Sprintf("authorization detail member '%s' must not be null", e.member)
}

func decodeAuthorizationDetailStrings(key string, value []byte) (values []string, err error) {
	var raw []*string

	if err = json.Unmarshal(value, &raw); err != nil {
		return nil, err
	}

	values = make([]string, len(raw))

	for i, v := range raw {
		if v == nil {
			return nil, &authorizationDetailNullMemberError{member: key, element: true}
		}

		values[i] = *v
	}

	return values, nil
}

func isAuthorizationDetailCommonMember(key string) bool {
	switch key {
	case authorizationDetailMemberType, authorizationDetailMemberLocations, authorizationDetailMemberActions,
		authorizationDetailMemberDataTypes, authorizationDetailMemberIdentifier, authorizationDetailMemberPrivileges:
		return true
	default:
		return false
	}
}

func decodeAuthorizationDetailValue(data []byte) (value any, err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err = decoder.Decode(&value); err != nil {
		return nil, err
	}

	return value, nil
}

func cloneAuthorizationDetailExtra(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}

	data, err := json.Marshal(extra)
	if err != nil {
		return maps.Clone(extra)
	}

	value, err := decodeAuthorizationDetailValue(data)
	if err != nil {
		return maps.Clone(extra)
	}

	clone, _ := value.(map[string]any)

	return clone
}

// AuthorizationDetailsTypeHandler implements a single RFC 9396 authorization details type.
type AuthorizationDetailsTypeHandler interface {
	// Type returns the authorization details type this handler implements.
	Type() string

	// Validate returns an error when the detail is not a conforming instance of the type: it contains unknown fields,
	// fields of the wrong type or with invalid values, or is missing required fields. Errors which are not an
	// *RFC6749Error are returned to the client as 'invalid_authorization_details'.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
	Validate(ctx context.Context, client Client, detail AuthorizationDetail) (err error)

	// Contains reports whether requested asks for no more than granted. When it returns true, requested is issued
	// verbatim, so it must return false for any member, common or Extra, that granted does not justify. It must not
	// mutate its arguments. It compares a single pair; CheckAuthorizationDetailsContained assigns each requested
	// detail a distinct granted detail, so one granted detail never justifies several requested details.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
	Contains(ctx context.Context, granted, requested AuthorizationDetail) (contained bool)
}

// AuthorizationDetailsClient restricts the RFC 9396 authorization details types a client may request. A nil list
// permits every type and a non-nil empty list permits none, so stores must preserve nil versus empty.
type AuthorizationDetailsClient interface {
	Client

	// GetAuthorizationDetailsTypes returns the authorization details types this client may request.
	GetAuthorizationDetailsTypes() (types []string)
}

// GetAuthorizationDetailsTypeHandlers returns the handlers from config when it implements
// AuthorizationDetailsTypeHandlersProvider, and nil otherwise.
func GetAuthorizationDetailsTypeHandlers(ctx context.Context, config any) map[string]AuthorizationDetailsTypeHandler {
	if provider, ok := config.(AuthorizationDetailsTypeHandlersProvider); ok {
		return provider.GetAuthorizationDetailsTypeHandlers(ctx)
	}

	return nil
}

// GetAuthorizationDetailsMaxObjects returns the maximum from config when it implements
// AuthorizationDetailsMaxObjectsProvider with a positive value, and the default of 32 otherwise.
func GetAuthorizationDetailsMaxObjects(ctx context.Context, config any) int {
	if provider, ok := config.(AuthorizationDetailsMaxObjectsProvider); ok {
		if maximum := provider.GetAuthorizationDetailsMaxObjects(ctx); maximum > 0 {
			return maximum
		}
	}

	return defaultAuthorizationDetailsMaxObjects
}

// CheckAuthorizationDetailsMaxObjects rejects details with more objects than GetAuthorizationDetailsMaxObjects allows.
// ParseRequestedAuthorizationDetails applies it; callers parsing details from any other source must apply it too.
func CheckAuthorizationDetailsMaxObjects(ctx context.Context, config any, details AuthorizationDetails) (err error) {
	if maximum := GetAuthorizationDetailsMaxObjects(ctx, config); len(details) > maximum {
		return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter must not contain more than %d authorization details objects.", maximum))
	}

	return nil
}

// IsAuthorizationDetailsEnabled reports whether at least one RFC 9396 authorization details type handler is
// configured.
func IsAuthorizationDetailsEnabled(ctx context.Context, config any) bool {
	return len(GetAuthorizationDetailsTypeHandlers(ctx, config)) != 0
}

// ValidateAuthorizationDetailsTypes rejects details of a type the client may not request or of a type with no
// configured handler. It does not call the type handler's Validate.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func ValidateAuthorizationDetailsTypes(ctx context.Context, config any, client Client, details AuthorizationDetails) (err error) {
	if len(details) == 0 {
		return nil
	}

	handlers := GetAuthorizationDetailsTypeHandlers(ctx, config)

	var allowed []string

	if c, ok := client.(AuthorizationDetailsClient); ok {
		allowed = c.GetAuthorizationDetailsTypes()
	}

	for _, detail := range details {
		if allowed != nil && !slices.Contains(allowed, detail.Type) {
			return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The OAuth 2.0 Client is not allowed to request authorization details type '%s'.", detail.Type))
		}

		if _, ok := handlers[detail.Type]; !ok {
			return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The authorization details type '%s' is not supported.", detail.Type))
		}
	}

	return nil
}

// ValidateAuthorizationDetails rejects details which fail ValidateAuthorizationDetailsTypes or which the type's
// handler does not accept.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func ValidateAuthorizationDetails(ctx context.Context, config any, client Client, details AuthorizationDetails) (err error) {
	if err = ValidateAuthorizationDetailsTypes(ctx, config, client, details); err != nil {
		return err
	}

	handlers := GetAuthorizationDetailsTypeHandlers(ctx, config)

	for _, detail := range details {
		if err = handlers[detail.Type].Validate(ctx, client, detail); err != nil {
			var rfc *RFC6749Error

			if errors.As(err, &rfc) {
				return errorsx.WithStack(err)
			}

			return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The authorization details object of type '%s' is invalid.", detail.Type).WithWrap(err).WithDebugError(err))
		}
	}

	return nil
}

// ParseRequestedAuthorizationDetails parses and validates the 'authorization_details' parameter of form. It returns
// nil without reading the parameter when no handlers are configured.
func ParseRequestedAuthorizationDetails(ctx context.Context, config any, client Client, form url.Values) (details AuthorizationDetails, err error) {
	if !IsAuthorizationDetailsEnabled(ctx, config) {
		return nil, nil
	}

	if details, err = ParseAuthorizationDetails(form.Get(consts.FormParameterAuthorizationDetails)); err != nil {
		return nil, err
	}

	if err = CheckAuthorizationDetailsMaxObjects(ctx, config, details); err != nil {
		return nil, err
	}

	if err = ValidateAuthorizationDetails(ctx, config, client, details); err != nil {
		return nil, err
	}

	return details, nil
}

// NarrowAuthorizationDetails settles the authorization details of a token request against the details granted to the
// underlying grant. A request without the 'authorization_details' parameter takes the granted details, and otherwise
// the requested details must be contained in the granted details. The settled details are recorded as the requested
// details of the request, and must be of types the client may request and the authorization server supports.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
func NarrowAuthorizationDetails(ctx context.Context, config any, request Requester, granted AuthorizationDetails) (err error) {
	if len(request.GetRequestedAuthorizationDetails()) == 0 {
		request.SetRequestedAuthorizationDetails(granted)
	} else if err = CheckAuthorizationDetailsContained(ctx, config, granted, request.GetRequestedAuthorizationDetails()); err != nil {
		return err
	}

	return ValidateAuthorizationDetailsTypes(ctx, config, request.GetClient(), request.GetRequestedAuthorizationDetails())
}

// CheckAuthorizationDetailsContained rejects the requested details unless each one can be assigned a distinct granted
// detail of the same type which contains it, so one granted detail never justifies more than one requested detail.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
func CheckAuthorizationDetailsContained(ctx context.Context, config any, granted, requested AuthorizationDetails) (err error) {
	handlers := GetAuthorizationDetailsTypeHandlers(ctx, config)

	candidates := make([][]int, len(requested))

	for i, r := range requested {
		handler, ok := handlers[r.Type]
		if !ok {
			return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The authorization details type '%s' is not supported.", r.Type))
		}

		for j, g := range granted {
			if g.Type == r.Type && handler.Contains(ctx, g, r) {
				candidates[i] = append(candidates[i], j)
			}
		}

		if len(candidates[i]) == 0 {
			return errAuthorizationDetailsNotGranted(r.Type)
		}
	}

	assigned := make([]int, len(granted))

	for j := range assigned {
		assigned[j] = -1
	}

	for i, r := range requested {
		if !assignAuthorizationDetail(i, candidates, assigned, make([]bool, len(granted))) {
			return errAuthorizationDetailsNotGranted(r.Type)
		}
	}

	return nil
}

func assignAuthorizationDetail(i int, candidates [][]int, assigned []int, visited []bool) bool {
	for _, j := range candidates[i] {
		if assigned[j] == -1 {
			assigned[j] = i

			return true
		}
	}

	for _, j := range candidates[i] {
		if visited[j] {
			continue
		}

		visited[j] = true

		if assignAuthorizationDetail(assigned[j], candidates, assigned, visited) {
			assigned[j] = i

			return true
		}
	}

	return false
}

func errAuthorizationDetailsNotGranted(t string) error {
	return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The requested authorization details of type '%s' were not granted by the resource owner.", t))
}
