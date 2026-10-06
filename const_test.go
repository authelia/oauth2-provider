// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"authelia.com/provider/oauth2/internal/gen"
)

const (
	prefixSchemeBasic = "Basic "
)

const (
	testRARDetailsJSON           = `[{"type":"payment_initiation","actions":["initiate"]}]`
	testRARMalformedJSON         = "not json"
	testRARNullJSON              = "null"
	testRARMemberType            = "type"
	testRARMemberActions         = "actions"
	testRARMemberCreditorName    = "creditorName"
	testRARMemberCustom          = "custom"
	testRARTypeOther             = "other"
	testRARActionInitiate        = "initiate"
	testRARActionStatus          = "status"
	testRARActionRead            = "read"
	testRARActionWrite           = "write"
	testRARIdentifierOther       = "acct-2"
	testRARValueChanged          = "changed"
	testRARDataTypeBalance       = "balance"
	testRARDataTypeAll           = "all"
	testRARPrivilegeAdmin        = "admin"
	testRARLocationA             = "https://a.example.com"
	testRARLocationB             = "https://b.example.com"
	testRARCreditorName          = "Merchant A"
	testRARClientID              = "rar-client"
	testRARIssuer                = "https://auth.example.com"
	testRARKeyID                 = "rs256-sig"
	testRARHintNotArray          = "The 'authorization_details' parameter must be a JSON array."
	testRARHintNotObject         = "The 'authorization_details' parameter element at index 0 must be a JSON object."
	testRARHintMissingType       = "The 'authorization_details' parameter element at index 0 must have a non-empty 'type'."
	testRARHintTypeNotAllowed    = "The OAuth 2.0 Client is not allowed to request authorization details type 'payment_initiation'."
	testRARHintNullPrivileges    = "The 'authorization_details' parameter element at index 0 member 'privileges' must not be null."
	testRARHintMaxObjectsDefault = "The 'authorization_details' parameter must not contain more than 32 authorization details objects."
	testRARHintNotGranted        = "The requested authorization details of type 'payment_initiation' were not granted by the resource owner."
	testRARHintClientCredentials = "The 'authorization_details' parameter is not supported for grant type 'client_credentials'."
)

const testPBES2RequestObjectSecret = "foobarfoobarfoobarfoobarfoobarfoobar"

const bclTestIssuer = "https://op.example/"

const introspectionCredentialURL = "https://as.example.com/introspect"

const testClientSecretKeyIDSecret = "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob"

const logoutTestIssuer = "https://issuer.example/"

var bclTestKey = gen.MustRSAKey()

var (
	testClientSecretFoo     = mustNewBCryptClientSecretPlain("foo")
	testClientSecretBar     = mustNewBCryptClientSecretPlain("bar")
	testClientSecret1234    = mustNewBCryptClientSecretPlain("1234")
	testClientSecretComplex = mustNewBCryptClientSecretPlain("foo %66%6F%6F@$<§!✓")
)

var logoutTestKey = gen.MustRSAKey()
