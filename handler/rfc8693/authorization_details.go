// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func carrySubjectAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, request oauth2.AccessRequester, original oauth2.Requester) {
	if !oauth2.IsAuthorizationDetailsEnabled(ctx, config) {
		return
	}

	// An exchanged access or refresh token carries the details granted to the 'subject_token' and no others.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-11.2
	switch requestedTokenTypeIdentifier(ctx, request, config) {
	case consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken:
		request.SetGrantedAuthorizationDetails(original.GetGrantedAuthorizationDetails())
	}
}

func assignAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, request oauth2.AccessRequester) (grant oauth2.AuthorizationDetails, err error) {
	if !oauth2.IsAuthorizationDetailsEnabled(ctx, config) {
		return nil, nil
	}

	grant = requestableAuthorizationDetails(ctx, config, request.GetClient(), request.GetGrantedAuthorizationDetails())

	var assigned oauth2.AuthorizationDetails

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
	if assigned, err = oauth2.AssignAuthorizationDetails(ctx, config, request, grant); err != nil {
		return nil, err
	}

	request.SetRequestedAuthorizationDetails(assigned)
	request.SetGrantedAuthorizationDetails(assigned)

	return grant, nil
}

func requestableAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, client oauth2.Client, details oauth2.AuthorizationDetails) (requestable oauth2.AuthorizationDetails) {
	for _, detail := range details {
		if oauth2.ValidateAuthorizationDetailsTypes(ctx, config, client, oauth2.AuthorizationDetails{detail}) == nil {
			requestable = append(requestable, detail)
		}
	}

	return requestable
}
