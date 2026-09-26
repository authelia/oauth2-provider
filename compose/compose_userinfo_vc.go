// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/verifiable"
)

// OIDCUserinfoVerifiableCredentialFactory creates a verifiable credentials' handler. The storage must implement
// verifiable.NonceManager, which no storage in this module does, so it panics when the storage does not.
func OIDCUserinfoVerifiableCredentialFactory(config oauth2.Configurator, storage, strategy any) any {
	manager, ok := storage.(verifiable.NonceManager)
	if !ok {
		panic("oauth2: OIDCUserinfoVerifiableCredentialFactory requires a storage implementing verifiable.NonceManager, but it was not provided")
	}

	return &verifiable.Handler{
		NonceManager: manager,
		Config:       config,
	}
}
