// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type AudienceMatchingStrategy func(haystack []string, needle []string) error

func DefaultAudienceMatchingStrategy(haystack []string, needle []string) error {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		nu, err := url.Parse(n)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to parse requested audience '%s'.", n).WithWrap(err).WithDebugError(err))
		}

		var found bool
		for _, h := range haystack {
			hu, err := url.Parse(h)
			if err != nil {
				return errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to parse whitelisted audience '%s'.", h).WithWrap(err).WithDebugError(err))
			}

			allowedPath := strings.TrimRight(hu.Path, "/")
			if nu.Scheme == hu.Scheme &&
				nu.Host == hu.Host &&
				(nu.Path == hu.Path ||
					nu.Path == allowedPath ||
					len(nu.Path) > len(allowedPath) && strings.TrimRight(nu.Path[:len(allowedPath)+1], "/")+"/" == allowedPath+"/") {
				found = true
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
		}
	}

	return nil
}

// ExactAudienceMatchingStrategy does not assume that audiences are URIs, but compares strings as-is and
// does matching with exact string comparison. It requires that all strings in "needle" are present in
// "haystack". Use this strategy when your audience values are not URIs (e.g., you use client IDs for
// audience and they are UUIDs or random strings).
func ExactAudienceMatchingStrategy(haystack []string, needle []string) error {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		var found bool
		for _, h := range haystack {
			if n == h {
				found = true
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf(`Requested audience "%s" has not been whitelisted by the OAuth 2.0 Client.`, n))
		}
	}

	return nil
}

// GetAudiences allows audiences to be provided as repeated "audience" form parameter,
// or as a space-delimited "audience" form parameter if it is not repeated.
// RFC 8693 in section 2.1 specifies that multiple audience values should be multiple
// query parameters, while RFC 6749 says that that request parameter must not be included
// more than once (and thus why we use space-delimited value). This function tries to satisfy both.
// If "audience" form parameter is repeated, we do not split the value by space.
func GetAudiences(form url.Values) []string {
	audiences := form[consts.FormParameterAudience]

	switch len(audiences) {
	case 1:
		return RemoveEmpty(strings.Split(audiences[0], " "))
	case 0:
		return []string{}
	default:
		return RemoveEmpty(audiences)
	}
}

//nolint:unparam
func (f *Fosite) validateAudience(ctx context.Context, r *http.Request, request Requester) error {
	audience := GetAudiences(request.GetRequestForm())

	if len(audience) == 0 && !request.GetRequestForm().Has(consts.FormParameterAudience) {
		if client, ok := request.GetClient().(RequestedAudienceImplicitClient); ok && client.GetRequestedAudienceImplicit() {
			audience = client.GetAudience()
		}
	} else if err := f.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), audience); err != nil {
		return err
	}

	request.SetRequestedAudience(audience)

	return nil
}
