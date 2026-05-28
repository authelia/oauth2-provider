package oauth2

import (
	"net/url"
	"strings"
)

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
