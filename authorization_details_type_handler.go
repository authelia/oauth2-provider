// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

// DefaultAuthorizationDetailsTypeHandler is a configurable AuthorizationDetailsTypeHandler for an RFC 9396
// authorization details type whose meaning belongs to the resource servers it is used with, so the authorization
// server needs only its shape and the values it may carry.
//
// A requested detail is validated against the permitted values of each common data field, the permitted
// type-specific members, the required fields, and the Validator. At the token endpoint each requested detail selects a
// distinct granted detail which contains it: its identifier, when present, is that of the granted detail, every value
// of each common data field is one the granted detail carries, and every type-specific member equals that of the
// granted detail. The assigned detail is the granted detail with each common data field the requested detail carries
// narrowed to its values. Without the 'authorization_details' parameter every granted detail is assigned.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
type DefaultAuthorizationDetailsTypeHandler struct {
	// Name is the authorization details type.
	Name string

	// Locations, Actions, DataTypes and Privileges are the values a detail may carry in the common data field of the
	// same name. Every value is permitted when nil, and none when empty.
	Locations  []string
	Actions    []string
	DataTypes  []string
	Privileges []string

	// Members are the names of the type-specific members a detail may carry. Every member is permitted when nil, and
	// none when empty.
	Members []string

	// Required are the names of the common data fields and type-specific members every detail requested for
	// authorization must carry. An array field must not be empty.
	Required []string

	// Validator is called for each detail requested for authorization after every other check passes, for checks the
	// fields above cannot express, such as a JSON Schema for the type-specific members.
	Validator func(ctx context.Context, request Requester, detail AuthorizationDetail) (err error)

	// LimitDisclosure discloses a detail which has locations only to resource servers they identify. A JWT access token
	// carries it only when every value of its audience is one of the locations, as every resource server in the
	// audience can read the token; a client needing details for several resource servers requests a token for each.
	// An introspection response carries it only when the identifier of the client making the request is one of the
	// locations. A detail without locations is disclosed to every resource server.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-9
	LimitDisclosure bool
}

// Type implements AuthorizationDetailsTypeHandler.
func (h *DefaultAuthorizationDetailsTypeHandler) Type() string {
	return h.Name
}

// Validate implements AuthorizationDetailsTypeHandler.
func (h *DefaultAuthorizationDetailsTypeHandler) Validate(ctx context.Context, request Requester, detail AuthorizationDetail) (err error) {
	if err = h.validatePermitted(detail); err != nil {
		return err
	}

	for _, name := range h.Required {
		if !hasAuthorizationDetailMember(detail, name) {
			return fmt.Errorf("the '%s' member is required", name)
		}
	}

	if h.Validator != nil {
		return h.Validator(ctx, request, detail)
	}

	return nil
}

// Assign implements AuthorizationDetailsTypeHandler.
func (h *DefaultAuthorizationDetailsTypeHandler) Assign(_ context.Context, _ AccessRequester, granted, requested AuthorizationDetails) (assigned AuthorizationDetails, err error) {
	if len(requested) == 0 {
		return granted, nil
	}

	for _, detail := range requested {
		if err = h.validatePermitted(detail); err != nil {
			return nil, err
		}
	}

	matches, ok := MatchAuthorizationDetails(granted, requested, containsAuthorizationDetail)
	if !ok {
		return nil, errors.New("the requested details are not contained in the granted details")
	}

	for i, r := range requested {
		detail := granted[matches[i]].Clone()

		if r.Locations != nil {
			detail.Locations = slices.Clone(r.Locations)
		}

		if r.Actions != nil {
			detail.Actions = slices.Clone(r.Actions)
		}

		if r.DataTypes != nil {
			detail.DataTypes = slices.Clone(r.DataTypes)
		}

		if r.Privileges != nil {
			detail.Privileges = slices.Clone(r.Privileges)
		}

		assigned = append(assigned, detail)
	}

	return assigned, nil
}

// Disclose implements AuthorizationDetailsTypeDisclosingHandler.
func (h *DefaultAuthorizationDetailsTypeHandler) Disclose(_ context.Context, _ Requester, recipient AuthorizationDetailsRecipient, details AuthorizationDetails) (disclosed AuthorizationDetails, err error) {
	if !h.LimitDisclosure {
		return details, nil
	}

	identifiers := recipient.Audience

	if recipient.Client != nil {
		identifiers = []string{recipient.Client.GetID()}
	}

	for _, detail := range details {
		if len(detail.Locations) == 0 || isEveryLocation(identifiers, detail.Locations) {
			disclosed = append(disclosed, detail)
		}
	}

	return disclosed, nil
}

func isEveryLocation(identifiers, locations []string) bool {
	if len(identifiers) == 0 {
		return false
	}

	for _, identifier := range identifiers {
		if !slices.Contains(locations, identifier) {
			return false
		}
	}

	return true
}

func (h *DefaultAuthorizationDetailsTypeHandler) validatePermitted(detail AuthorizationDetail) (err error) {
	for _, field := range []struct {
		name      string
		values    []string
		permitted []string
	}{
		{authorizationDetailMemberLocations, detail.Locations, h.Locations},
		{authorizationDetailMemberActions, detail.Actions, h.Actions},
		{authorizationDetailMemberDataTypes, detail.DataTypes, h.DataTypes},
		{authorizationDetailMemberPrivileges, detail.Privileges, h.Privileges},
	} {
		if field.permitted == nil {
			continue
		}

		for _, value := range field.values {
			if !slices.Contains(field.permitted, value) {
				return fmt.Errorf("the '%s' value '%s' is not permitted", field.name, value)
			}
		}
	}

	if h.Members == nil {
		return nil
	}

	for name := range detail.Extra {
		if !slices.Contains(h.Members, name) {
			return fmt.Errorf("the '%s' member is not permitted", name)
		}
	}

	return nil
}

func hasAuthorizationDetailMember(detail AuthorizationDetail, name string) bool {
	switch name {
	case authorizationDetailMemberType:
		return detail.Type != ""
	case authorizationDetailMemberLocations:
		return len(detail.Locations) != 0
	case authorizationDetailMemberActions:
		return len(detail.Actions) != 0
	case authorizationDetailMemberDataTypes:
		return len(detail.DataTypes) != 0
	case authorizationDetailMemberPrivileges:
		return len(detail.Privileges) != 0
	case authorizationDetailMemberIdentifier:
		return detail.Identifier != nil
	default:
		_, ok := detail.Extra[name]

		return ok
	}
}

func containsAuthorizationDetail(granted, requested AuthorizationDetail) bool {
	if requested.Identifier != nil && (granted.Identifier == nil || *requested.Identifier != *granted.Identifier) {
		return false
	}

	for _, field := range [][2][]string{
		{granted.Locations, requested.Locations},
		{granted.Actions, requested.Actions},
		{granted.DataTypes, requested.DataTypes},
		{granted.Privileges, requested.Privileges},
	} {
		for _, value := range field[1] {
			if !slices.Contains(field[0], value) {
				return false
			}
		}
	}

	for name, value := range requested.Extra {
		if g, ok := granted.Extra[name]; !ok || !reflect.DeepEqual(g, value) {
			return false
		}
	}

	return true
}

var (
	_ AuthorizationDetailsTypeHandler           = (*DefaultAuthorizationDetailsTypeHandler)(nil)
	_ AuthorizationDetailsTypeDisclosingHandler = (*DefaultAuthorizationDetailsTypeHandler)(nil)
)
