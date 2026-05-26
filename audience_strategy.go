// SPDX-FileCopyrightText: 2026 Authelia
//
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
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Unable to parse requested audience '%s'.", n).WithWrap(err))
		}

		var found bool
		for _, h := range haystack {
			hu, err := url.Parse(h)
			if err != nil {
				return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Unable to parse whitelisted audience '%s'.", h).WithWrap(err))
			}

			allowedPath := strings.TrimRight(hu.Path, "/")
			if nu.Scheme == hu.Scheme &&
				nu.Host == hu.Host &&
				(nu.Path == hu.Path ||
					nu.Path == allowedPath ||
					len(nu.Path) > len(allowedPath) && strings.TrimRight(nu.Path[:len(allowedPath)+1], "/")+"/" == allowedPath+"/") {
				found = true

				break
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
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
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf(`Requested audience "%s" has not been whitelisted by the OAuth 2.0 Client.`, n))
		}
	}

	return nil
}

// ValidateResourceIndicators validates resource and audience parameters ensuring they don't conflict and are properly formatted.
// Returns an error if validation fails, such as when URIs are not absolute or contain a fragment.
func ValidateResourceIndicators(form url.Values, allowLegacy bool) (err error) {
	hasResource := form.Has(consts.FormParameterResource)
	hasAudience := form.Has(consts.FormParameterAudience)

	if !hasResource && !hasAudience {
		return nil
	}

	if hasResource && hasAudience && allowLegacy {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'resource' parameter is only allowed when the 'audience' parameter is not also present."))
	}

	if hasAudience && allowLegacy {
		return nil
	}

	resources := GetRequestedResources(form, allowLegacy)

	for _, resource := range resources {
		if err = ValidateResourceIndicatorURI(resource); err != nil {
			return err
		}
	}

	return nil
}

// ValidateResourceIndicatorURI validates a single resource indicator URI.
func ValidateResourceIndicatorURI(resource string) (err error) {
	var uri *url.URL

	if uri, err = url.Parse(resource); err != nil {
		return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Unable to parse resource indicator '%s' from the 'resource' parameter.", resource).WithWrap(err))
	}

	if !uri.IsAbs() {
		return errorsx.WithStack(ErrInvalidTarget.WithDebugf("The 'resource' parameter must contain resource indicators that are absolute URIs but '%s' is not absolute.", resource))
	}

	if uri.Fragment != "" {
		return errorsx.WithStack(ErrInvalidTarget.WithDebugf("The 'resource' parameter must contain resource indicators that do not contain a fragment but '%s' contains a fragment.", resource))
	}

	return nil
}

// GetResourcesParameter returns the resource identifiers from the given form parameter.
func GetResourcesParameter(parameter string, form url.Values) (resources []string, ok bool) {
	if resources, ok = form[parameter]; !ok {
		return []string{}, false
	}

	switch len(resources) {
	case 1:
		resources = RemoveEmpty(strings.Split(resources[0], " "))

		return resources, len(resources) > 0
	case 0:
		return []string{}, false
	default:
		resources = RemoveEmpty(resources)

		return resources, len(resources) > 0
	}
}

// GetRequestedResources allows audiences to be provided as repeated "audience" form parameter,
// or as a space-delimited "audience" form parameter if it is not repeated.
// RFC 8693 in section 2.1 specifies that multiple audience values should be multiple
// query parameters, while RFC 6749 says that that request parameter must not be included
// more than once (and thus why we use space-delimited value). This function tries to satisfy both.
// If "audience" form parameter is repeated, we do not split the value by space.
func GetRequestedResources(form url.Values, allowLegacy bool) (audiences []string) {
	var ok bool

	if audiences, ok = GetResourcesParameter(consts.FormParameterResource, form); ok {
		return audiences
	}

	if allowLegacy {
		if audiences, ok = GetResourcesParameter(consts.FormParameterAudience, form); ok {
			return audiences
		}
	}

	return []string{}
}

func HasRequestedResource(form url.Values, allowLegacy bool) bool {
	return form.Has(consts.FormParameterResource) || (allowLegacy && form.Has(consts.FormParameterAudience))
}

//nolint:unparam
func (f *Fosite) validateAudience(ctx context.Context, r *http.Request, request Requester) error {
	audience := GetRequestedResources(request.GetRequestForm(), f.Config.GetUseLegacyResourceIdentifierParameter(ctx))

	if len(audience) == 0 && !HasRequestedResource(request.GetRequestForm(), f.Config.GetUseLegacyResourceIdentifierParameter(ctx)) {
		if client, ok := request.GetClient().(RequestedAudienceImplicitClient); ok && client.GetRequestedAudienceImplicit() {
			audience = client.GetAudience()
		}
	} else if err := f.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), audience); err != nil {
		return err
	}

	request.SetRequestedAudience(audience)

	return nil
}
