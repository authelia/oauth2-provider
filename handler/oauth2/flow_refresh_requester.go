// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"maps"

	"authelia.com/provider/oauth2"
)

func refreshTokenRequester(request oauth2.AccessRequester, grant oauth2.Requester) (requester oauth2.Requester) {
	if restorer, ok := request.(oauth2.RefreshTokenAccessRequester); ok {
		return restorer.SanitizeRestoreRefreshTokenOriginalRequester(grant)
	}

	requester = grant.Sanitize([]string{})

	requester.SetSession(request.GetSession())
	requester.SetRequestedAt(request.GetRequestedAt())

	if form := requester.GetRequestForm(); form != nil {
		clear(form)
		maps.Copy(form, request.Sanitize([]string{}).GetRequestForm())
	}

	return requester
}
