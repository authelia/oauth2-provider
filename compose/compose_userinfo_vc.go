// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/verifiable"
)

// OIDCUserinfoVerifiableCredentialFactory creates a verifiable credentials' handler.
func OIDCUserinfoVerifiableCredentialFactory(config oauth2.Configurator, storage, strategy any) any {
	return &verifiable.Handler{
		NonceManager: storage.(verifiable.NonceManager),
		Config:       config,
	}
}
