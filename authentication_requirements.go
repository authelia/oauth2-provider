// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// isAuthenticationRequirementsEnforced returns true if the configuration implements
// AuthenticationRequirementsEnforcementProvider and enables enforcement.
func (f *Fosite) isAuthenticationRequirementsEnforced(ctx context.Context) (enforced bool) {
	provider, ok := f.Config.(AuthenticationRequirementsEnforcementProvider)

	return ok && provider.GetEnforceAuthenticationRequirements(ctx)
}

// validateAuthenticationRequirements returns ErrUnmetAuthenticationRequirements unless the 'acr' recorded on the ID
// Token claims of the session is one of the requested 'acr_values' and the 'auth_time' is no older than 'max_age'
// seconds before the request. A malformed 'max_age' returns ErrInvalidRequest.
func validateAuthenticationRequirements(request Requester, session Session) (err error) {
	form := request.GetRequestForm()

	requested := strings.Fields(form.Get(consts.FormParameterAuthenticationContextClassReferenceValues))

	values, hasMaxAge := form[consts.FormParameterMaximumAge]

	if len(requested) == 0 && !hasMaxAge {
		return nil
	}

	login := &jwt.IDTokenClaims{}

	if s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims }); ok && s.IDTokenClaims() != nil {
		login = s.IDTokenClaims()
	}

	// See: https://www.rfc-editor.org/rfc/rfc9470#section-5
	if len(requested) != 0 && (login.AuthenticationContextClassReference == "" || !slices.Contains(requested, login.AuthenticationContextClassReference)) {
		return errorsx.WithStack(ErrUnmetAuthenticationRequirements.WithHint("The Authentication Context Class Reference requested by the 'acr_values' parameter was not met."))
	}

	if !hasMaxAge {
		return nil
	}

	var maxAge int64

	if len(values) != 1 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Parameter 'max_age' must be provided exactly once."))
	}

	if maxAge, err = strconv.ParseInt(values[0], 10, 64); err != nil || maxAge < 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Parameter 'max_age' must be a non-negative integer.").WithWrap(err).WithDebugError(err))
	}

	// See: https://www.rfc-editor.org/rfc/rfc9470#section-3 and https://www.rfc-editor.org/rfc/rfc9470#section-5
	if login.AuthTime == nil || login.AuthTime.IsZero() || login.AuthTime.Add(time.Duration(maxAge)*time.Second).Before(request.GetRequestedAt().Truncate(jwt.TimePrecision)) {
		return errorsx.WithStack(ErrUnmetAuthenticationRequirements.WithHint("The End-User authentication is older than the 'max_age' parameter allows."))
	}

	return nil
}
