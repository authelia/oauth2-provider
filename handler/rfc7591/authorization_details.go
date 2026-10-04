// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// CheckAuthorizationDetailsTypes rejects 'authorization_details_types' values with no configured
// oauth2.AuthorizationDetailsTypeHandler. While RFC 9396 is disabled the field is unsupported metadata, so it is
// cleared rather than validated, persisted or echoed.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-10
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func CheckAuthorizationDetailsTypes(ctx context.Context, config any, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata == nil {
		return nil
	}

	if !oauth2.IsAuthorizationDetailsEnabled(ctx, config) {
		metadata.AuthorizationDetailsTypes = nil

		return nil
	}

	handlers := oauth2.GetAuthorizationDetailsTypeHandlers(ctx, config)

	for _, value := range metadata.AuthorizationDetailsTypes {
		if _, ok := handlers[value]; !ok {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The 'authorization_details_types' value '%s' is not supported by this authorization server.", value))
		}
	}

	return nil
}
