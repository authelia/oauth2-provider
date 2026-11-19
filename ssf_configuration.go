// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// SSFSpecVersion is the 'spec_version' of the implemented final specification.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
const SSFSpecVersion = "1_0"

// SSFAuthorizationSchemeOAuth2 is the 'spec_urn' of the OAuth 2.0 authorization scheme, which the CAEP
// Interoperability Profile requires the Transmitter Configuration Metadata to list.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.3.7
const SSFAuthorizationSchemeOAuth2 = "urn:ietf:rfc:6749"

// SSFDefaultSubjectsAll and SSFDefaultSubjectsNone are the values of the 'default_subjects' Transmitter Configuration
// Metadata member.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
const (
	SSFDefaultSubjectsAll  = "ALL"
	SSFDefaultSubjectsNone = "NONE"
)

const (
	ssfConfigurationWellKnownPath = "/.well-known/ssf-configuration"

	ssfMetadataIssuer                = "issuer"
	ssfMetadataSpecVersion           = "spec_version"
	ssfMetadataJWKSURI               = "jwks_uri"
	ssfMetadataDeliveryMethods       = "delivery_methods_supported"
	ssfMetadataConfigurationEndpoint = "configuration_endpoint"
	ssfMetadataStatusEndpoint        = "status_endpoint"
	ssfMetadataAddSubjectEndpoint    = "add_subject_endpoint"
	ssfMetadataRemoveSubjectEndpoint = "remove_subject_endpoint"
	ssfMetadataVerificationEndpoint  = "verification_endpoint"
	ssfMetadataAuthorizationSchemes  = "authorization_schemes"
	ssfMetadataDefaultSubjects       = "default_subjects"
)

// SSFConfiguration is the Transmitter Configuration Metadata.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
type SSFConfiguration struct {
	SpecVersion              string                   `json:"spec_version,omitempty"`
	Issuer                   string                   `json:"issuer"`
	JWKSURI                  string                   `json:"jwks_uri,omitempty"`
	DeliveryMethodsSupported []string                 `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint    string                   `json:"configuration_endpoint,omitempty"`
	StatusEndpoint           string                   `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint       string                   `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint    string                   `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint     string                   `json:"verification_endpoint,omitempty"`
	CriticalSubjectMembers   []string                 `json:"critical_subject_members,omitempty"`
	AuthorizationSchemes     []SSFAuthorizationScheme `json:"authorization_schemes,omitempty"`
	DefaultSubjects          string                   `json:"default_subjects,omitempty"`
}

// SSFAuthorizationScheme is an authorization scheme entry of the Transmitter Configuration Metadata.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1
type SSFAuthorizationScheme struct {
	SpecURN string `json:"spec_urn"`
}

// WriteSSFConfiguration writes the Transmitter Configuration Metadata as 'application/json', with no parameter. Members
// with zero elements are omitted. Metadata that ValidateSSFConfiguration refuses is not written, and the response is a
// 'server_error' with status 500.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.3
func (f *Fosite) WriteSSFConfiguration(ctx context.Context, rw http.ResponseWriter, configuration *SSFConfiguration) {
	if err := f.ValidateSSFConfiguration(ctx, configuration); err != nil {
		f.WriteSSFError(ctx, rw, nil, err)

		return
	}

	data, err := json.Marshal(configuration)
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.MediaTypeApplicationJSON)

	_, _ = rw.Write(data)
}

// ValidateSSFConfiguration returns an error matching ErrServerError for Transmitter Configuration Metadata that must
// not be published, which is metadata ValidateSSFConfigurationForIssuer refuses for the configured issuer, GetIssuer,
// the 'iss' of every Security Event Token. SSFConfig.EnforceCAEPInteroperabilityProfile selects the profile rules.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.3
func (f *Fosite) ValidateSSFConfiguration(ctx context.Context, configuration *SSFConfiguration) (err error) {
	config := f.getSSFConfig(ctx)

	if err = ValidateSSFConfigurationForIssuer(configuration, f.Config.GetIssuer(ctx), config != nil && config.EnforceCAEPInteroperabilityProfile); err != nil {
		return errorsx.WithStack(ErrServerError.WithDebug(err.Error()))
	}

	return nil
}

// ValidateSSFConfigurationForIssuer returns an error for Transmitter Configuration Metadata that is not valid for the
// issuer, which a Transmitter must not publish and a Receiver must not use:
//
//   - The 'issuer' must be an issuer SSFConfigurationURL accepts and identical to the given issuer (SSF Section 7.1,
//     Section 7.2.4).
//   - 'jwks_uri' is required, since every Security Event Token is signed (SSF Section 7.1).
//   - 'jwks_uri' and each endpoint that is present must be an absolute https URL with no userinfo or fragment (SSF
//     Section 7.1).
//   - 'default_subjects', when present, must be 'ALL' or 'NONE' (SSF Section 7.1).
//   - Each entry of 'authorization_schemes' must have a 'spec_urn' (SSF Section 7.1.1).
//
// With profile it must also have a 'spec_version' of '1_0' or greater, 'delivery_methods_supported',
// 'configuration_endpoint', 'status_endpoint', 'verification_endpoint', and 'authorization_schemes' with the
// SSFAuthorizationSchemeOAuth2 entry (Profile Section 2.3.1 to 2.3.7).
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.4
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.3
func ValidateSSFConfigurationForIssuer(configuration *SSFConfiguration, issuer string, profile bool) (err error) {
	if configuration == nil {
		return errors.New("The Transmitter Configuration Metadata is missing.")
	}

	if _, err = SSFConfigurationURL(configuration.Issuer); err != nil {
		return errors.Errorf("The Transmitter Configuration Metadata '%s' is not valid: %s.", ssfMetadataIssuer, err)
	}

	if configuration.Issuer != issuer {
		return errors.Errorf("The Transmitter Configuration Metadata '%s' is not the configured issuer.", ssfMetadataIssuer)
	}

	if configuration.JWKSURI == "" {
		return errors.Errorf("The Transmitter Configuration Metadata '%s' is required.", ssfMetadataJWKSURI)
	}

	for _, member := range configuration.endpoints() {
		if member.value != "" && !isSSFEndpointURL(member.value) {
			return errors.Errorf("The Transmitter Configuration Metadata '%s' must be an absolute https URL.", member.name)
		}
	}

	switch configuration.DefaultSubjects {
	case "", SSFDefaultSubjectsAll, SSFDefaultSubjectsNone:
		break
	default:
		return errors.Errorf("The Transmitter Configuration Metadata '%s' must be 'ALL' or 'NONE'.", ssfMetadataDefaultSubjects)
	}

	for _, scheme := range configuration.AuthorizationSchemes {
		if scheme.SpecURN == "" {
			return errors.Errorf("The Transmitter Configuration Metadata '%s' has an entry with no 'spec_urn'.", ssfMetadataAuthorizationSchemes)
		}
	}

	if !profile {
		return nil
	}

	if member := configuration.interoperabilityProfileFault(); member != "" {
		return errors.Errorf("The Transmitter Configuration Metadata '%s' does not meet the CAEP Interoperability Profile.", member)
	}

	return nil
}

type ssfMetadataMember struct {
	name, value string
}

func (c *SSFConfiguration) endpoints() (members []ssfMetadataMember) {
	return []ssfMetadataMember{
		{ssfMetadataJWKSURI, c.JWKSURI},
		{ssfMetadataConfigurationEndpoint, c.ConfigurationEndpoint},
		{ssfMetadataStatusEndpoint, c.StatusEndpoint},
		{ssfMetadataAddSubjectEndpoint, c.AddSubjectEndpoint},
		{ssfMetadataRemoveSubjectEndpoint, c.RemoveSubjectEndpoint},
		{ssfMetadataVerificationEndpoint, c.VerificationEndpoint},
	}
}

func (c *SSFConfiguration) interoperabilityProfileFault() (member string) {
	switch {
	case !isSSFSpecVersionFinal(c.SpecVersion):
		return ssfMetadataSpecVersion
	case len(c.DeliveryMethodsSupported) == 0:
		return ssfMetadataDeliveryMethods
	case c.ConfigurationEndpoint == "":
		return ssfMetadataConfigurationEndpoint
	case c.StatusEndpoint == "":
		return ssfMetadataStatusEndpoint
	case c.VerificationEndpoint == "":
		return ssfMetadataVerificationEndpoint
	case !slices.Contains(c.AuthorizationSchemes, SSFAuthorizationScheme{SpecURN: SSFAuthorizationSchemeOAuth2}):
		return ssfMetadataAuthorizationSchemes
	default:
		return ""
	}
}

func isSSFSpecVersionFinal(version string) (is bool) {
	// Profile Section 2.3.1: '1_0' or greater. A suffix names an implementer's draft, which precedes its final version.
	number, _, draft := strings.Cut(version, "-")

	left, right, ok := strings.Cut(number, "_")
	if !ok {
		return false
	}

	major, err := strconv.ParseUint(left, 10, 32)
	if err != nil {
		return false
	}

	minor, err := strconv.ParseUint(right, 10, 32)
	if err != nil {
		return false
	}

	switch {
	case major != 1:
		return major > 1
	case minor != 0:
		return true
	default:
		return !draft
	}
}

// SSFConfigurationURL returns the Transmitter Configuration Metadata location of the issuer, inserting
// '/.well-known/ssf-configuration' between the host and the path and removing any terminating '/' first. The issuer must
// be an https URL with a host and no userinfo, query or fragment, an empty one included (SSF Section 7.1), so that it is
// the same string in the metadata, in the 'iss' of a Security Event Token and at the location derived from it.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2
func SSFConfigurationURL(issuer string) (uri string, err error) {
	var u *url.URL

	if u, err = url.Parse(issuer); err != nil {
		return "", errors.New("issuer is not a valid URL")
	}

	if !u.IsAbs() || u.Hostname() == "" {
		return "", errors.New("issuer must be an absolute URL")
	}

	if u.Scheme != consts.SchemeHTTPS {
		return "", errors.New("issuer must use the https scheme")
	}

	if u.User != nil {
		return "", errors.New("issuer must not contain userinfo")
	}

	if u.RawQuery != "" || u.ForceQuery || strings.Contains(issuer, "#") {
		return "", errors.New("issuer must not contain a query or fragment")
	}

	raw := strings.TrimSuffix(u.EscapedPath(), "/")

	var path string

	if path, err = url.PathUnescape(raw); err != nil {
		return "", errors.New("issuer is not a valid URL")
	}

	u.Path, u.RawPath = ssfConfigurationWellKnownPath+path, ssfConfigurationWellKnownPath+raw

	return u.String(), nil
}
