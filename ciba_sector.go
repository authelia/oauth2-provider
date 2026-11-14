// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// SectorIdentifierClient is a Client which has registered a 'sector_identifier_uri'.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2
type SectorIdentifierClient interface {
	Client

	// GetSectorIdentifierURI returns the 'sector_identifier_uri' client metadata value, or an empty string.
	GetSectorIdentifierURI() (uri string)
}

// SubjectTypeClient is a Client which has registered a 'subject_type'.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2
type SubjectTypeClient interface {
	Client

	// GetSubjectType returns the 'subject_type' client metadata value: 'public', 'pairwise', or an empty string.
	GetSubjectType() (subjectType string)
}

// CIBASectorIdentifierHost returns the sector identifier host used for pairwise subject computation of a CIBA
// client: the host of the 'sector_identifier_uri', else the host of the 'jwks_uri' for the poll and ping modes, else
// the host of the 'backchannel_client_notification_endpoint' for the push mode.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func CIBASectorIdentifierHost(client Client) (host string, err error) {
	var raw string

	if c, ok := client.(SectorIdentifierClient); ok {
		raw = c.GetSectorIdentifierURI()
	}

	if raw == "" {
		switch GetCIBADeliveryMode(client) {
		case consts.CIBAModePoll, consts.CIBAModePing:
			if c, ok := client.(JSONWebKeysClient); ok {
				raw = c.GetJSONWebKeysURI()
			}
		case consts.CIBAModePush:
			if c, ok := client.(CIBAClient); ok {
				raw = c.GetBackChannelClientNotificationEndpoint()
			}
		}
	}

	if raw == "" {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint("The client has no registered URI from which the CIBA sector identifier host can be determined."))
	}

	var parsed *url.URL

	if parsed, err = url.Parse(raw); err != nil || parsed.Hostname() == "" {
		return "", errorsx.WithStack(ErrInvalidClient.WithHintf("The client registered URI '%s' has no host from which the CIBA sector identifier host can be determined.", raw))
	}

	return strings.ToLower(parsed.Hostname()), nil
}
