// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

const (
	rrbTokenEndpoint = "https://as.example.com/token"
	rrbClientID      = "rotation-binding-client"
	rrbRedirectURI   = "https://rp.example.com/cb"
)

const (
	bothClientID    = "both-client"
	bothSecret      = "both-client-secret"
	bothRedirectURI = "https://rp.example.com/cb"
	bothTokenURI    = "https://as.example.com/token"
)

const (
	mtTokenEndpoint = "https://as.example.com/token"
	mtClientID      = "mtls-client"
	mtSecret        = "mtls-client-secret"
	mtRedirectURI   = "https://rp.example.com/cb"
)

const (
	chainClientID           = "dpop-chain-client"
	chainSecret             = "dpop-chain-client-secret"
	chainIntrospectEndpoint = "https://as.example.com/introspect"
)

const (
	parEndpoint    = "https://as.example.com/par"
	parRedirectURI = "https://rp.example.com/cb"
	parClientID    = "par-client"
	parSecret      = "par-client-secret"
)

const (
	rtTokenEndpoint = "https://as.example.com/token"
	rtClientID      = "refresh-client"
	rtSecret        = "refresh-client-secret"
	rtRedirectURI   = "https://rp.example.com/cb"
)
