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

type AudienceMatchingStrategy func(haystack, needle []string) (err error)

// ResourceMatchingStrategy matches requested RFC 8707 resource indicators against the client's
// allowed audience list. Defaults to DefaultAudienceMatchingStrategy (URL-based matching).
type ResourceMatchingStrategy func(haystack, needle []string) (err error)

func DefaultAudienceMatchingStrategy(haystack, needle []string) (err error) {
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
func ExactAudienceMatchingStrategy(haystack, needle []string) (err error) {
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

// ValidateResourceIndicators validates the 'resource' form parameter values as RFC 8707
// resource indicators. Values from the 'audience' form parameter are not URI-validated here —
// they are checked against the client's allowed audience list by the audience strategy.
func ValidateResourceIndicators(form url.Values) (err error) {
	resources, ok := GetResourcesParameter(consts.FormParameterResource, form)
	if !ok {
		return nil
	}

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

// GetRequestedResources returns the values of the RFC 8707 'resource' form parameter.
// Multiple resources can be expressed as repeated parameters or as a single space-delimited value.
func GetRequestedResources(form url.Values) (resources []string) {
	if values, ok := GetResourcesParameter(consts.FormParameterResource, form); ok {
		return values
	}

	return []string{}
}

// GetRequestedAudiences returns the values of the 'audience' form parameter.
// Multiple audiences can be expressed as repeated parameters or as a single space-delimited value.
func GetRequestedAudiences(form url.Values) (audiences []string) {
	if values, ok := GetResourcesParameter(consts.FormParameterAudience, form); ok {
		return values
	}

	return []string{}
}

// JoinGrantedAudienceAndResource returns the concatenation of the granted audience and resource
// indicator values, deduplicated, for use as the 'aud' claim in tokens and introspection responses.
func JoinGrantedAudienceAndResource(audience, resource Arguments) Arguments {
	if len(audience) == 0 && len(resource) == 0 {
		return nil
	}

	merged := make(Arguments, 0, len(audience)+len(resource))
	seen := make(map[string]struct{}, len(audience)+len(resource))

	for _, v := range audience {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		merged = append(merged, v)
	}

	for _, v := range resource {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		merged = append(merged, v)
	}

	return merged
}

//nolint:unparam
func (f *Fosite) validateAudience(ctx context.Context, r *http.Request, request Requester) error {
	form := request.GetRequestForm()

	audience := GetRequestedAudiences(form)
	resource := GetRequestedResources(form)

	if len(audience) == 0 && len(resource) == 0 && !form.Has(consts.FormParameterAudience) && !form.Has(consts.FormParameterResource) {
		if client, ok := request.GetClient().(RequestedAudienceImplicitClient); ok && client.GetRequestedAudienceImplicit() {
			audience = client.GetAudience()
		}
	} else {
		if err := f.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), audience); err != nil {
			return err
		}

		if err := f.Config.GetResourceStrategy(ctx)(request.GetClient().GetAudience(), resource); err != nil {
			return err
		}
	}

	request.SetRequestedAudience(audience)
	request.SetRequestedResource(resource)

	return nil
}
