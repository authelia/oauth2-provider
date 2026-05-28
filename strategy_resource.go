package oauth2

import (
	"context"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ResourceStrategy matches requested RFC 8707 resource indicators against the client's
// allowed audience list. Defaults to DefaultAudienceStrategy (URL-based matching).
type ResourceStrategy func(haystack, needle []string) (err error)

// GetResourceStrategy resolves the ResourceStrategy to use for a request. If the client implements
// ResourceStrategyProvider and returns a non-nil strategy, the client's strategy is preferred over the global
// configuration. Otherwise the strategy from the provided config is used, falling back to DefaultResourceStrategy
// when neither source supplies one.
func GetResourceStrategy(ctx context.Context, config ResourceStrategyProvider, client Client) (strategy ResourceStrategy) {
	if client != nil {
		if c, ok := client.(ResourceStrategyProvider); ok {
			strategy = c.GetResourceStrategy(ctx)
		}
	}

	if strategy == nil {
		strategy = config.GetResourceStrategy(ctx)

		if strategy == nil {
			strategy = DefaultResourceStrategy
		}
	}

	return strategy
}

// DefaultResourceStrategy matches requested RFC 8707 resource indicators against the client's
// allowed audience list.
func DefaultResourceStrategy(haystack, needle []string) (err error) {
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

// GetRequestedResources returns the values of the RFC 8707 'resource' form parameter.
// Multiple resources can be expressed as repeated parameters or as a single space-delimited value.
func GetRequestedResources(form url.Values) (resources []string) {
	if values, ok := GetResourcesParameter(consts.FormParameterResource, form); ok {
		return values
	}

	return []string{}
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
