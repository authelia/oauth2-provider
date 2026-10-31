// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
)

// SSFSpecVersion is the 'spec_version' of the implemented final specification.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
const SSFSpecVersion = "1_0"

const ssfConfigurationWellKnownPath = "/.well-known/ssf-configuration"

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

// WriteSSFConfiguration writes the Transmitter Configuration Metadata as 'application/json'. Members with zero
// elements are omitted.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.3
func (f *Fosite) WriteSSFConfiguration(ctx context.Context, rw http.ResponseWriter, configuration *SSFConfiguration) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	_ = json.NewEncoder(rw).Encode(configuration)
}

// SSFConfigurationURL returns the Transmitter Configuration Metadata location of the issuer, inserting
// '/.well-known/ssf-configuration' between the host and the path and removing any terminating '/' first. The issuer must
// be an https URL with no query or fragment (SSF Section 7.1).
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2
func SSFConfigurationURL(issuer string) (uri string, err error) {
	var u *url.URL

	if u, err = url.Parse(issuer); err != nil {
		return "", errors.New("issuer is not a valid URL")
	}

	if !u.IsAbs() || u.Host == "" {
		return "", errors.New("issuer must be an absolute URL")
	}

	if u.Scheme != "https" {
		return "", errors.New("issuer must use the https scheme")
	}

	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
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
