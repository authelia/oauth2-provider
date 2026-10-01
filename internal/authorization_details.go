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
// 'payment_initiation' example. Its Contains treats a common member omitted from the requested detail as no wider than
// the granted one, which suits only types where an absent member does not mean unrestricted.
type PaymentInitiationTypeHandler struct{}

func (PaymentInitiationTypeHandler) Type() string {
	return AuthorizationDetailsTypePaymentInitiation
}

func (PaymentInitiationTypeHandler) Validate(_ context.Context, _ oauth2.Client, detail oauth2.AuthorizationDetail) error {
	if len(detail.Actions) == 0 {
		return errors.New("actions is required")
	}

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

func (PaymentInitiationTypeHandler) Contains(_ context.Context, granted, requested oauth2.AuthorizationDetail) bool {
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
