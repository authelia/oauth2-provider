// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

const (
	testRARActionInitiate       = "initiate"
	testRARActionStatus         = "status"
	testRARActionCancel         = "cancel"
	testRARIdentifierEnriched   = "enriched"
	testRARExtraSpoofed         = "spoofed"
	testRARHintTypeNotAllowed   = "The OAuth 2.0 Client is not allowed to request authorization details type 'payment_initiation'."
	testRARHintTypeNotSupported = "The authorization details type 'payment_initiation' is not supported."
)
