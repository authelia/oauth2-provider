// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2"
)

func refreshTokenRequester(request oauth2.AccessRequester, grant oauth2.Requester) (requester oauth2.Requester) {
	if restorer, ok := request.(oauth2.RefreshTokenAccessRequester); ok {
		return restorer.SanitizeRestoreRefreshTokenOriginalRequester(grant)
	}

	requester = request.Sanitize([]string{})

	requester.SetRequestedAuthorizationDetails(grant.GetRequestedAuthorizationDetails())
	requester.SetGrantedAuthorizationDetails(grant.GetGrantedAuthorizationDetails())

	return requester
}
