// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
)

// WellKnownOAuthProtectedResourceSuffix is the well-known URI suffix of the protected resource metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-3
const WellKnownOAuthProtectedResourceSuffix = consts.WellKnownOAuthProtectedResourceSuffix

// ProtectedResourcesProvider is optionally implemented by the Configurator to list the protected resources advertised
// in the 'protected_resources' authorization server metadata parameter.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-4
type ProtectedResourcesProvider interface {
	// GetProtectedResources returns the resource identifiers of the protected resources that can be used with this
	// authorization server.
	GetProtectedResources(ctx context.Context) (resources []string)
}

// ProtectedResourceMetadata is the OAuth 2.0 Protected Resource Metadata document. A parameter with a zero value is
// omitted, except that a non-nil empty BearerMethodsSupported is kept as it states that no bearer method is supported.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2
type ProtectedResourceMetadata struct {
	Resource                              string   `json:"resource,omitempty"`
	AuthorizationServers                  []string `json:"authorization_servers,omitempty"`
	JWKSURI                               string   `json:"jwks_uri,omitempty"`
	ScopesSupported                       []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported                []string `json:"bearer_methods_supported,omitzero"`
	ResourceSigningAlgValuesSupported     []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName                          string   `json:"resource_name,omitempty"`
	ResourceDocumentation                 string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                     string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                        string   `json:"resource_tos_uri,omitempty"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthorizationDetailsTypesSupported    []string `json:"authorization_details_types_supported,omitempty"`
	DPoPSigningAlgValuesSupported         []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DPoPBoundAccessTokensRequired         bool     `json:"dpop_bound_access_tokens_required,omitempty"`

	// SignedMetadata is the JWT asserting the metadata parameters as claims.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2.2
	SignedMetadata string `json:"signed_metadata,omitempty"`

	// Extra is the additional parameters and the language-tagged human-readable parameters such as 'resource_name#en',
	// which are members of the top-level JSON object. A key naming a parameter this type defines is an error. A zero
	// value is emitted as given, so omitting it as Section 3.2 requires is left to the caller.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2.1 and
	// https://datatracker.ietf.org/doc/html/rfc9728#section-3.2
	Extra map[string]any `json:"-"`
}

// MarshalJSON implements [json.Marshaler]. It returns an error when a key of Extra names a parameter this type defines.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-3.2
func (m ProtectedResourceMetadata) MarshalJSON() (data []byte, err error) {
	if data, err = json.Marshal(protectedResourceMetadata(m)); err != nil {
		return nil, err
	}

	if len(m.Extra) == 0 {
		return data, nil
	}

	for name := range m.Extra {
		if isProtectedResourceMetadataParameter(name) {
			return nil, fmt.Errorf("the protected resource metadata extra parameter '%s' collides with a defined parameter", name)
		}
	}

	var extra []byte

	if extra, err = json.Marshal(m.Extra); err != nil {
		return nil, err
	}

	if len(data) == 2 {
		return extra, nil
	}

	data = append(data[:len(data)-1], ',')

	return append(data, extra[1:]...), nil
}

// UnmarshalJSON implements [json.Unmarshaler]. A member this type does not define is stored in Extra, with numbers
// decoded as [json.Number].
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2
func (m *ProtectedResourceMetadata) UnmarshalJSON(data []byte) (err error) {
	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return err
	}

	if members == nil {
		return nil
	}

	var (
		metadata protectedResourceMetadata
		extra    map[string]any
	)

	defined := make(map[string]json.RawMessage, len(members))

	for name, raw := range members {
		if isProtectedResourceMetadataParameter(name) {
			defined[name] = raw

			continue
		}

		var value any

		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()

		if err = decoder.Decode(&value); err != nil {
			return err
		}

		if extra == nil {
			extra = make(map[string]any, len(members))
		}

		extra[name] = value
	}

	if data, err = json.Marshal(defined); err != nil {
		return err
	}

	if err = json.Unmarshal(data, &metadata); err != nil {
		return err
	}

	*m = ProtectedResourceMetadata(metadata)
	m.Extra = extra

	return nil
}

// NewProtectedResourceMetadata returns the protected resource metadata of the resource identifier which the
// configuration determines: the authorization server, and the DPoP, mutual TLS and authorization details capabilities.
// It returns an error unless the resource identifier is an absolute 'https' URL without a fragment component. The
// remaining parameters are left to the caller.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2
func (f *Fosite) NewProtectedResourceMetadata(ctx context.Context, resource string) (metadata *ProtectedResourceMetadata, err error) {
	if _, err = parseProtectedResourceIdentifier(resource); err != nil {
		return nil, err
	}

	metadata = &ProtectedResourceMetadata{
		Resource:                              resource,
		TLSClientCertificateBoundAccessTokens: f.Config.GetMTLSEnabled(ctx),
	}

	if issuer := f.Config.GetIssuer(ctx); issuer != "" {
		metadata.AuthorizationServers = []string{issuer}
	}

	if _, ok := f.Config.GetDPoPStrategy(ctx).(DPoPResourceStrategy); ok && f.Config.GetDPoPEnabled(ctx) {
		metadata.DPoPSigningAlgValuesSupported = slices.Clone(f.Config.GetDPoPAllowedJWSAlgorithms(ctx))
		metadata.DPoPBoundAccessTokensRequired = f.Config.GetDPoPEnforce(ctx)
	}

	if rar := f.rfc9396Metadata(ctx); rar != nil {
		metadata.AuthorizationDetailsTypesSupported = rar.AuthorizationDetailsTypesSupported
	}

	return metadata, nil
}

// SignProtectedResourceMetadata sets the 'signed_metadata' parameter to a JWT asserting the other metadata parameters as
// claims, signed with the discovery metadata signing strategy and with the issuer as the 'iss' claim. A previous value
// is discarded. It returns an error when the strategy or the issuer is not configured.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-2.2
func (f *Fosite) SignProtectedResourceMetadata(ctx context.Context, metadata *ProtectedResourceMetadata) (err error) {
	if metadata == nil {
		return errors.New("unable to sign the protected resource metadata: the metadata is nil")
	}

	metadata.SignedMetadata = ""

	strategy := f.Config.GetDiscoveryMetadataSigningStrategy(ctx)
	if strategy == nil {
		return errors.New("unable to sign the protected resource metadata: the discovery metadata signing strategy is not configured")
	}

	issuer := f.Config.GetIssuer(ctx)
	if issuer == "" {
		return errors.New("unable to sign the protected resource metadata: the issuer is not configured")
	}

	var signed string

	if signed, err = signMetadataDocument(ctx, strategy, metadata, "protected resource metadata", issuer); err != nil {
		return err
	}

	metadata.SignedMetadata = signed

	return nil
}

// WriteProtectedResourceMetadata writes the protected resource metadata as a 200 JSON response, or a 500 without a
// body when it is nil or cannot be marshaled. Caching headers are left to the caller.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-3.2
func (f *Fosite) WriteProtectedResourceMetadata(ctx context.Context, rw http.ResponseWriter, metadata *ProtectedResourceMetadata) {
	if metadata == nil {
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	f.WriteDiscoveryResponse(ctx, rw, metadata)
}

// ProtectedResourceMetadataWellKnownURL returns the protected resource metadata URL of the resource identifier, with
// the well-known URI path suffix inserted between the host and the path, a terminating slash following the host
// removed, and the query kept. It returns an error unless the resource identifier is an absolute 'https' URL without a
// fragment component.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-3.1
func ProtectedResourceMetadataWellKnownURL(resource string) (location string, err error) {
	var u *url.URL

	if u, err = parseProtectedResourceIdentifier(resource); err != nil {
		return "", err
	}

	location = u.Scheme + "://" + u.Host + "/.well-known/" + WellKnownOAuthProtectedResourceSuffix

	if path := u.EscapedPath(); path != "/" {
		location += path
	}

	if u.RawQuery != "" {
		location += "?" + u.RawQuery
	}

	return location, nil
}

type protectedResourceMetadata ProtectedResourceMetadata

func parseProtectedResourceIdentifier(resource string) (u *url.URL, err error) {
	if u, err = url.Parse(resource); err != nil {
		return nil, fmt.Errorf("the resource '%s' is not a valid URL: %w", resource, err)
	}

	if u.Scheme == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("the resource '%s' must be an absolute URL", resource)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("the resource '%s' must use the 'https' scheme", resource)
	}

	if u.User != nil {
		return nil, fmt.Errorf("the resource '%s' must not have a userinfo component", resource)
	}

	if strings.Contains(resource, "#") {
		return nil, fmt.Errorf("the resource '%s' must not have a fragment component", resource)
	}

	return u, nil
}

func isProtectedResourceMetadataParameter(name string) bool {
	switch name {
	case consts.ProtectedResourceMetadataResource,
		consts.ProtectedResourceMetadataAuthorizationServers,
		consts.DiscoveryJWKSURI,
		consts.DiscoveryScopesSupported,
		consts.ProtectedResourceMetadataBearerMethodsSupported,
		consts.ProtectedResourceMetadataResourceSigningAlgValuesSupported,
		consts.ProtectedResourceMetadataResourceName,
		consts.ProtectedResourceMetadataResourceDocumentation,
		consts.ProtectedResourceMetadataResourcePolicyURI,
		consts.ProtectedResourceMetadataResourceTOSURI,
		consts.DiscoveryTLSClientCertificateBoundAccessTokens,
		consts.DiscoveryAuthorizationDetailsTypesSupported,
		consts.DiscoveryDPoPSigningAlgValuesSupported,
		consts.DiscoveryDPoPBoundAccessTokensRequired,
		consts.DiscoverySignedMetadata:
		return true
	default:
		return false
	}
}
