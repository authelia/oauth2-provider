// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
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

// GetRequestedACRValues returns the Authentication Context Class References requested for the End-User authentication
// of request: the 'acr_values' parameter when present, otherwise the 'default_acr_values' of a DefaultACRValuesClient
// unless the 'claims' parameter requests the 'acr' Claim with a 'value' or 'values' member.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest and
// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func GetRequestedACRValues(request Requester) (values []string) {
	if values = strings.Fields(request.GetRequestForm().Get(consts.FormParameterAuthenticationContextClassReferenceValues)); len(values) != 0 {
		return values
	}

	if r, ok := request.(ClaimsRequester); ok {
		if claims := r.GetClaims(); claims != nil && (claims.IDToken[consts.ClaimAuthenticationContextClassReference].HasValues() || claims.UserInfo[consts.ClaimAuthenticationContextClassReference].HasValues()) {
			return nil
		}
	}

	if client, ok := request.GetClient().(DefaultACRValuesClient); ok {
		return slices.Clone(client.GetDefaultACRValues())
	}

	return nil
}

// GetRequestedMaxAge returns the Maximum Authentication Age in seconds requested for the End-User authentication of
// request: the 'max_age' parameter when present, otherwise the 'default_max_age' of a DefaultMaxAgeClient. A value of 0
// is distinct from none as it is equivalent to 'prompt=login', and a 'max_age' parameter which is not provided exactly
// once as a non-negative integer is an error rather than read as absent.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest and
// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func GetRequestedMaxAge(request Requester) (maxAge int64, ok bool, err error) {
	if values, present := request.GetRequestForm()[consts.FormParameterMaximumAge]; present && len(values) != 0 {
		if len(values) != 1 {
			return 0, false, fmt.Errorf("the parameter was provided %d times but must be provided exactly once", len(values))
		}

		if maxAge, err = strconv.ParseInt(values[0], 10, 64); err != nil || maxAge < 0 {
			return 0, false, fmt.Errorf("the value '%s' could not be parsed as a non-negative integer", values[0])
		}

		return maxAge, true, nil
	}

	if client, ok := request.GetClient().(DefaultMaxAgeClient); ok {
		if maxAge, ok = client.GetDefaultMaxAge(); ok && maxAge >= 0 {
			return maxAge, true, nil
		}
	}

	return 0, false, nil
}

// IsAuthenticationWithinMaxAge reports whether an End-User authentication at authTime is no older than maxAge seconds
// at the time at. The age is compared in seconds and nanoseconds rather than as a [time.Duration], so a maxAge of any
// size and any two times are compared exactly.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func IsAuthenticationWithinMaxAge(authTime, at time.Time, maxAge int64) (within bool) {
	if !authTime.Before(at) {
		return true
	}

	// The difference wraps like the Unix seconds of a time before the earliest Unix second, so it is exact whenever the
	// age fits an int64, and is negative only for an age of more seconds than an int64 holds, which is beyond any maxAge.
	seconds, nanoseconds := at.Unix()-authTime.Unix(), at.Nanosecond()-authTime.Nanosecond()

	if seconds < 0 {
		return false
	}

	if nanoseconds < 0 {
		seconds--
	}

	return seconds < maxAge || (seconds == maxAge && nanoseconds == 0)
}

// validateAuthenticationRequirements returns ErrUnmetAuthenticationRequirements unless the 'acr' recorded on the ID
// Token claims of the session is one of the values GetRequestedACRValues returns and the 'auth_time' is no older than
// the seconds GetRequestedMaxAge returns before the request. A malformed 'max_age' returns ErrInvalidRequest.
func validateAuthenticationRequirements(request Requester, session Session) (err error) {
	requested := GetRequestedACRValues(request)

	maxAge, hasMaxAge, err := GetRequestedMaxAge(request)
	if err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Parameter 'max_age' must be a non-negative integer.").WithWrap(err).WithDebugError(err))
	}

	if len(requested) == 0 && !hasMaxAge {
		return nil
	}

	login := &jwt.IDTokenClaims{}

	if s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims }); ok && s.IDTokenClaims() != nil {
		login = s.IDTokenClaims()
	}

	// See: https://www.rfc-editor.org/rfc/rfc9470#section-5
	if len(requested) != 0 && (login.AuthenticationContextClassReference == "" || !slices.Contains(requested, login.AuthenticationContextClassReference)) {
		return errorsx.WithStack(ErrUnmetAuthenticationRequirements.WithHint("The Authentication Context Class Reference requested by the 'acr_values' parameter or the 'default_acr_values' of the client was not met."))
	}

	if !hasMaxAge {
		return nil
	}

	// See: https://www.rfc-editor.org/rfc/rfc9470#section-3 and https://www.rfc-editor.org/rfc/rfc9470#section-5
	if login.AuthTime == nil || login.AuthTime.IsZero() || !IsAuthenticationWithinMaxAge(login.AuthTime.Time, request.GetRequestedAt().Truncate(jwt.TimePrecision), maxAge) {
		return errorsx.WithStack(ErrUnmetAuthenticationRequirements.WithHint("The End-User authentication is older than the 'max_age' parameter or the 'default_max_age' of the client allows."))
	}

	return nil
}
