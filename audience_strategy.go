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


// DefaultAudienceMatchingStrategy matches requested audiences against the client's allowed audience list.
func DefaultAudienceMatchingStrategy(haystack, needle []string) (err error) {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		var found bool

		for _, h := range haystack {
			if h == n {
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

// ResourceMatchingStrategy matches requested RFC 8707 resource indicators against the client's
// allowed audience list. Defaults to DefaultAudienceMatchingStrategy (URL-based matching).
type ResourceMatchingStrategy func(haystack, needle []string) (err error)

// DefaultResourceMatchingStrategy matches requested RFC 8707 resource indicators against the client's
// allowed audience list.
func DefaultResourceMatchingStrategy(haystack, needle []string) (err error) {
	if len(needle) == 0 {
		return nil
	}

	var nu, hu *url.URL

	for _, n := range needle {
		if nu, err = url.Parse(n); err != nil {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Requested resource '%s' could not be parsed.", n).WithWrap(err))
		}

		var found bool
		for _, h := range haystack {
			if hu, err = url.Parse(h); err != nil {
				continue
			}

			if IsMatchingResourceIndicator(hu, nu) {
				found = true

				break
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidTarget.WithDebugf("Requested resource '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
		}
	}

	return nil
}

// IsMatchingResourceIndicator returns true if needleURL is a subpath of haystackURL.
func IsMatchingResourceIndicator(haystackURL, needleURL *url.URL) bool {
	if needleURL.Scheme != haystackURL.Scheme || needleURL.Host != haystackURL.Host {
		return false
	}

	return isPathOrSubpath(haystackURL.Path, needleURL.Path)
}

// isPathOrSubpath reports whether needlePath equals haystackPath or is a sub-path of it,
// after normalizing trailing slashes. A sub-path must break on a path-segment boundary
// so that '/users' does NOT match '/users123' but DOES match '/users/123'.
//
// Match — exact:
//
//	haystack=/api/users    needle=/api/users     ✓
//
// Match — trailing slash on either side:
//
//	haystack=/api/users/   needle=/api/users     ✓
//	haystack=/api/users    needle=/api/users/    ✓
//
// Match — needle is a sub-path under the haystack:
//
//	haystack=/api/users    needle=/api/users/42  ✓
//
// No match — prefix without a segment boundary, or sibling path:
//
//	haystack=/api/users    needle=/api/users123  ✗
//	haystack=/api/users    needle=/api/tenants   ✗
func isPathOrSubpath(haystackPath, needlePath string) bool {
	// 1. Exact equality, with whatever trailing slashes both sides happen to have.
	if needlePath == haystackPath {
		return true
	}

	// Strip any trailing '/' off the haystack so 'allowed' is the canonical form.
	allowed := strings.TrimRight(haystackPath, "/")

	// 2. Needle equals haystack-without-trailing-slash. Handles the case where the
	//    haystack has a trailing slash but the needle does not.
	if needlePath == allowed {
		return true
	}

	// 3. Needle is strictly longer than the allowed haystack path AND the byte right
	//    after the haystack prefix is a '/'. We check that boundary by taking
	//    needle[:len(allowed)+1] and trimming a trailing '/' off — the result has to
	//    equal `allowed`. (Equivalently: needle starts with allowed + "/".)
	if len(needlePath) <= len(allowed) {
		return false
	}

	return strings.TrimRight(needlePath[:len(allowed)+1], "/")+"/" == allowed+"/"
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

				break
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
