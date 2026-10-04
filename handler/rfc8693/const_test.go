// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"authelia.com/provider/oauth2/internal/gen"
)

const (
	idjagSubject        = "peter"
	idjagClientID       = "my-client"
	idjagIssuer         = "https://as.example.com"
	idjagSubjectToken   = "subject"
	idjagSubjectType    = "urn:spec:jwt"
	idjagScope          = "chat.read"
	idjagAudience       = "https://rs.example.com/"
	idjagOtherClient    = "some-other-client"
	idjagOtherOwner     = "custom-lifespan-client"
	idjagOtherScope     = "chat.history"
	idjagOtherAudience  = "https://other.example.com/"
	idjagResource       = "https://rs.example.com/api"
	idjagOtherResource  = "https://other.example.com/api"
	idjagACR            = "urn:example:acr:mfa"
	idjagAMR            = "otp"
	idjagActionInitiate = "initiate"
	idjagActionStatus   = "status"
)

const (
	bindingJKT      = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	bindingJKTOther = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	bindingX5T      = "A4DtL2JmUMhAsvJj5tAtEqYFn7uHnaMbNKmoNcE7dnE"
)

var key = gen.MustRSAKey()
