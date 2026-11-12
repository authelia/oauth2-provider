// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func grantedAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, request oauth2.AccessRequester) (granted oauth2.AuthorizationDetails) {
	if !oauth2.IsAuthorizationDetailsEnabled(ctx, config) {
		return nil
	}

	// An exchanged access or refresh token carries the details granted to the 'subject_token' and no others.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-11.2
	switch requestedTokenTypeIdentifier(ctx, request, config) {
	case consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken:
	default:
		return nil
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return nil
	}

	subject := session.GetSubjectRequester()
	if subject == nil {
		return nil
	}

	return requestableAuthorizationDetails(ctx, config, request.GetClient(), subject.GetGrantedAuthorizationDetails())
}

func assignAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, request oauth2.AccessRequester) (err error) {
	if !oauth2.IsAuthorizationDetailsEnabled(ctx, config) || requestedTokenTypeIdentifier(ctx, request, config) != consts.TokenTypeRFC8693AccessToken {
		return nil
	}

	var assigned oauth2.AuthorizationDetails

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
	if assigned, err = oauth2.AssignAuthorizationDetails(ctx, config, request, grantedAuthorizationDetails(ctx, config, request)); err != nil {
		return err
	}

	request.SetRequestedAuthorizationDetails(assigned)
	request.SetGrantedAuthorizationDetails(assigned)

	return nil
}

func requestableAuthorizationDetails(ctx context.Context, config oauth2.RFC8693ConfigProvider, client oauth2.Client, details oauth2.AuthorizationDetails) (requestable oauth2.AuthorizationDetails) {
	for _, detail := range details {
		if oauth2.ValidateAuthorizationDetailsTypes(ctx, config, client, oauth2.AuthorizationDetails{detail}) == nil {
			requestable = append(requestable, detail)
		}
	}

	return requestable
}
