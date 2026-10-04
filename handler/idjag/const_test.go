// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

const (
	issueSubject     = "peter"
	issueClient      = "my-client"
	issueFiles       = "https://api.chat.example/files"
	issueAudienceURN = "urn:example:chat"
	issueEmail       = "person@example.com"
	issueACRGold     = "urn:acr:gold"
	issueACRSilver   = "urn:acr:silver"
	issueACRBronze   = "urn:acr:bronze"
	issueAMRMFA      = "mfa"
	issueAMRPassword = "pwd"

	issueAudienceTyped = "urn:example:typed"
	issueAudienceNone  = "urn:example:none"
	issueOtherType     = "other_type"
)

const (
	redeemSubject  = "U019488227"
	redeemClient   = "f53f191f9311af35"
	redeemResource = "https://api.chat.example/"
	redeemOther    = "https://other.example/"
	redeemEvil     = "https://evil.example/"
	redeemKeyID    = "idp"
	redeemOffline  = "offline_access"
	redeemNoGrant  = "no-grant"
	redeemPublic   = "public"
	redeemDPoP     = "dpop"
	redeemOtherJKT = "other-thumbprint"
	redeemAlice    = "alice"
	redeemRead     = "chat.read"
	redeemHistory  = "chat.history"
	redeemAdmin    = "chat.admin"
	redeemIssuer   = "https://idp.example/"
	redeemAudience = "https://chat.example/"
	redeemJKT      = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	redeemJWKSURI  = "https://idp.example/jwks"
	redeemEndpoint = "https://chat.example/token"

	redeemActionInitiate = "initiate"
	redeemActionRead     = "read"
	redeemMemberType     = "type"
	redeemMemberActions  = "actions"
	redeemMalformed      = "not-an-array"
)
