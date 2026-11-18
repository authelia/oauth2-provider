// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/grantmgmt"
)

// GrantManagementFactory creates the OpenID Grant Management for OAuth 2.0 handler. It panics if the storage does not
// implement oauth2.GrantManagementStorage.
//
// It MUST be registered before CIBADecisionFactory.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5
func GrantManagementFactory(config oauth2.Configurator, storage any, strategy any) any {
	store, ok := storage.(oauth2.GrantManagementStorage)
	if !ok {
		panic("oauth2: GrantManagementFactory requires a storage implementing oauth2.GrantManagementStorage")
	}

	return &grantmgmt.Handler{
		Config:  config,
		Storage: store,
	}
}
