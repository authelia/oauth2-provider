// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"authelia.com/provider/oauth2"
)

const AuthorizationDetailsTypePaymentInitiation = "payment_initiation"

// PaymentInitiationTypeHandler is a test oauth2.AuthorizationDetailsTypeHandler modelled on the RFC 9396 Section 2
// 'payment_initiation' example. A requested detail of a token request selects a distinct granted detail: each member it
// carries must be within that of the granted detail, and the assigned detail is the granted detail narrowed to the
// common members it carries.
type PaymentInitiationTypeHandler struct{}

func (PaymentInitiationTypeHandler) Type() string {
	return AuthorizationDetailsTypePaymentInitiation
}

func (PaymentInitiationTypeHandler) Validate(_ context.Context, _ oauth2.Requester, detail oauth2.AuthorizationDetail) error {
	if len(detail.Actions) == 0 {
		return errors.New("actions is required")
	}

	return validatePaymentInitiationMembers(detail)
}

func (PaymentInitiationTypeHandler) Assign(_ context.Context, _ oauth2.AccessRequester, granted, requested oauth2.AuthorizationDetails) (assigned oauth2.AuthorizationDetails, err error) {
	if len(requested) == 0 {
		return granted, nil
	}

	for _, detail := range requested {
		if err = validatePaymentInitiationMembers(detail); err != nil {
			return nil, err
		}
	}

	matches, ok := oauth2.MatchAuthorizationDetails(granted, requested, containsPaymentInitiation)
	if !ok {
		return nil, errors.New("the requested details are not contained in the granted details")
	}

	for i, r := range requested {
		detail := granted[matches[i]].Clone()

		if r.Actions != nil {
			detail.Actions = r.Actions
		}

		if r.Locations != nil {
			detail.Locations = r.Locations
		}

		if r.DataTypes != nil {
			detail.DataTypes = r.DataTypes
		}

		if r.Privileges != nil {
			detail.Privileges = r.Privileges
		}

		assigned = append(assigned, detail)
	}

	return assigned, nil
}

func validatePaymentInitiationMembers(detail oauth2.AuthorizationDetail) error {
	for _, action := range detail.Actions {
		if !slices.Contains([]string{"initiate", "status", "cancel"}, action) {
			return fmt.Errorf("action '%s' is unknown", action)
		}
	}

	for key := range detail.Extra {
		if !slices.Contains([]string{"instructedAmount", "creditorName", "creditorAccount", "remittanceInformationUnstructured"}, key) {
			return fmt.Errorf("field '%s' is unknown", key)
		}
	}

	return nil
}

func containsPaymentInitiation(granted, requested oauth2.AuthorizationDetail) bool {
	if requested.Identifier != nil && (granted.Identifier == nil || *requested.Identifier != *granted.Identifier) {
		return false
	}

	if !isSubset(granted.Actions, requested.Actions) || !isSubset(granted.Locations, requested.Locations) ||
		!isSubset(granted.DataTypes, requested.DataTypes) || !isSubset(granted.Privileges, requested.Privileges) {
		return false
	}

	for key, value := range requested.Extra {
		if !reflect.DeepEqual(granted.Extra[key], value) {
			return false
		}
	}

	return true
}

func isSubset(superset, subset []string) bool {
	for _, value := range subset {
		if !slices.Contains(superset, value) {
			return false
		}
	}

	return true
}

// AuthorizationDetailsClient is a test oauth2.AuthorizationDetailsClient.
type AuthorizationDetailsClient struct {
	*oauth2.DefaultClient

	AuthorizationDetailsTypes []string
}

func (c *AuthorizationDetailsClient) GetAuthorizationDetailsTypes() []string {
	return c.AuthorizationDetailsTypes
}
