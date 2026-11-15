// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// ClientCredentialsGrantStorage is the storage the client credentials grant requires.
type ClientCredentialsGrantStorage interface {
	AccessTokenStorage
}
