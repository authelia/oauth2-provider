// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AudienceStrategy matches requested audience values against the client's allowed audience list.
// It returns nil when every needle is permitted and an error otherwise.
type AudienceStrategy func(haystack, needle []string) (err error)

// GetAudienceStrategy resolves the AudienceStrategy to use for a request. If the client implements
// AudienceStrategyProvider and returns a non-nil strategy, the client's strategy is preferred over the global
// configuration. Otherwise the strategy from the provided config is used, falling back to DefaultAudienceStrategy
// when neither source supplies one.
func GetAudienceStrategy(ctx context.Context, config AudienceStrategyProvider, client Client) (strategy AudienceStrategy) {
	if client != nil {
		if c, ok := client.(AudienceStrategyProvider); ok {
			strategy = c.GetAudienceStrategy(ctx)
		}
	}

	if strategy == nil {
		strategy = config.GetAudienceStrategy(ctx)

		if strategy == nil {
			strategy = DefaultAudienceStrategy
		}
	}

	return strategy
}

// DefaultAudienceStrategy matches requested audiences against the client's allowed audience list.
func DefaultAudienceStrategy(haystack, needle []string) (err error) {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		if !slices.Contains(haystack, n) {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
		}
	}

	return nil
}

// ExactAudienceStrategy does not assume that audiences are URIs, but compares strings as-is and
// does matching with exact string comparison. It requires that all strings in "needle" are present in
// "haystack". Use this strategy when your audience values are not URIs (e.g., you use client IDs for
// audience and they are UUIDs or random strings).
func ExactAudienceStrategy(haystack, needle []string) (err error) {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		if !slices.Contains(haystack, n) {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf(`Requested audience "%s" has not been whitelisted by the OAuth 2.0 Client.`, n))
		}
	}

	return nil
}

// WildcardAudienceStrategy matches requested audiences against the client's allowed audience list. A requested audience
// must equal an allowed value exactly, or begin with the prefix of an allowed value which ends with '/*'. The prefix must
// be an absolute URI with a host and no query, so the wildcard only ever spans a path, and a requested audience carrying a
// fragment, a dot segment or an encoded slash never matches a wildcard. Any other allowed value, including one which is not
// a URI, is compared exactly. It applies only when configured as the AudienceStrategy.
func WildcardAudienceStrategy(haystack, needle []string) (err error) {
	for _, n := range needle {
		if !isMatchingWildcardTarget(haystack, n) {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
		}
	}

	return nil
}

// GetRequestedAudiences returns the values of the 'audience' form parameter.
// Multiple audiences can be expressed as repeated parameters or as a single space-delimited value.
func GetRequestedAudiences(form url.Values) (audiences []string) {
	if values, ok := GetResourcesParameter(consts.FormParameterAudience, form); ok {
		return values
	}

	return []string{}
}

//nolint:unparam
func (f *Fosite) validateAudience(ctx context.Context, r *http.Request, request Requester) error {
	form := request.GetRequestForm()

	return ValidateRequestedAudienceAndResource(ctx, f.Config, request, GetRequestedAudiences(form), GetRequestedResources(form))
}

// ValidateRequestedAudienceAndResource sets the requested audience and RFC 8707 resource indicators on the request.
// When neither the 'audience' nor the 'resource' parameter is present, a RequestedAudienceResourceImplicitClient may
// implicitly request all of its permitted audiences and resource indicators. Otherwise the provided values are matched
// against the client's permitted values using the effective AudienceStrategy and ResourceStrategy.
func ValidateRequestedAudienceAndResource(ctx context.Context, config AudienceResourceStrategyProvider, request Requester, audience, resource []string) (err error) {
	client := request.GetClient()
	form := request.GetRequestForm()

	if len(audience) == 0 && len(resource) == 0 && !form.Has(consts.FormParameterAudience) && !form.Has(consts.FormParameterResource) {
		if c, ok := client.(RequestedAudienceResourceImplicitClient); ok {
			if c.GetRequestedAudienceImplicit() {
				audience = c.GetAudience()
			}

			if c.GetRequestedResourceImplicit() {
				resource = c.GetResource()
			}
		}
	} else {
		if err = GetAudienceStrategy(ctx, config, client)(client.GetAudience(), audience); err != nil {
			return err
		}

		if err = GetResourceStrategy(ctx, config, client)(client.GetResource(), resource); err != nil {
			return err
		}
	}

	request.SetRequestedAudience(audience)
	request.SetRequestedResource(resource)

	return nil
}
