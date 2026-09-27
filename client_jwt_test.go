// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2/token/jwt"
)

var (
	_ jwt.JARMClient                  = JARMClient(nil)
	_ jwt.JWTProfileAccessTokenClient = JWTProfileClient(nil)
	_ jwt.IntrospectionClient         = IntrospectionJWTResponseClient(nil)
	_ jwt.IDTokenClient               = IDTokenClient(nil)
	_ jwt.UserInfoClient              = UserInfoClient(nil)
)
