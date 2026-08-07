// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DefaultClientRegistrationStrategy is the default oauth2.ClientRegistrationStrategy implementation. It produces and
// patches oauth2.DefaultRegisteredClient values, mapping every oauth2.ClientRegistrationMetadata field to its
// corresponding oauth2.DefaultRegisteredClient field one-for-one. It is zero-value usable.
type DefaultClientRegistrationStrategy struct{}

// NewDefaultClientRegistrationStrategy returns a new *DefaultClientRegistrationStrategy.
func NewDefaultClientRegistrationStrategy() (strategy *DefaultClientRegistrationStrategy) {
	return &DefaultClientRegistrationStrategy{}
}

// NewClient constructs a new *oauth2.DefaultRegisteredClient from the given id, secret, and metadata.
func (s *DefaultClientRegistrationStrategy) NewClient(ctx context.Context, id string, secret oauth2.ClientSecret, metadata *oauth2.ClientRegistrationMetadata) (client oauth2.Client, err error) {
	registered := &oauth2.DefaultRegisteredClient{
		DefaultClient:    &oauth2.DefaultClient{},
		ClientIDIssuedAt: time.Now().UTC(),
	}

	s.apply(registered, metadata)

	registered.ID = id
	registered.ClientSecret = secret

	return registered, nil
}

// PatchClient applies the complete metadata set onto an existing *oauth2.DefaultRegisteredClient, implementing the
// full replacement semantics of RFC 7592 Section 2.2: client metadata absent from the update is removed, not
// merged. Values which are not client metadata are preserved across the replacement, since RFC 7592's replacement
// semantics govern client metadata and not server policy the client does not control. Those are registration
// bookkeeping (id, issuance time, secret expiry, rotated secrets) and locally administered policy with no
// ClientRegistrationMetadata source (PKCE enforcement, JWT profile access tokens, PAR context lifespan). Public is
// NOT preserved: apply derives it from TokenEndpointAuthMethod on every call, so a client switching to or from "none"
// is reflected rather than fighting a stale value. A nil secret leaves the existing client secret untouched.
//
// The patched client is a new value and client is never written to. A oauth2.ClientStorage implementation is free to
// return a pointer into its own state from GetClient, as MemoryStore does, so patching in place would apply the
// replacement to the stored client before the caller persists it, leaving the update applied even on a request that
// goes on to fail. Returning a new value keeps the store's copy authoritative until UpdateClient succeeds.
func (s *DefaultClientRegistrationStrategy) PatchClient(ctx context.Context, client oauth2.Client, secret oauth2.ClientSecret, metadata *oauth2.ClientRegistrationMetadata) (patched oauth2.Client, err error) {
	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The default client registration strategy can only patch a '*oauth2.DefaultRegisteredClient' but the client with id '%s' is a '%T'.", client.GetID(), client))
	}

	replacement := &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{}}

	s.apply(replacement, metadata)

	// RFC 7592 Section 2.2 replacement semantics govern client metadata: everything the metadata does not carry is
	// reset, which the fresh value above already expresses. They do not govern registration bookkeeping or
	// server-administered policy, which have no ClientRegistrationMetadata source and so must be carried across
	// from the existing client explicitly rather than left at zero value.
	replacement.ID = registered.ID
	replacement.ClientIDIssuedAt = registered.ClientIDIssuedAt
	replacement.RotatedClientSecrets = registered.RotatedClientSecrets
	replacement.ClientSecretExpiresAt = registered.ClientSecretExpiresAt
	replacement.EnforcePKCE = registered.EnforcePKCE
	replacement.EnforcePKCEChallengeMethod = registered.EnforcePKCEChallengeMethod
	replacement.PKCEChallengeMethod = registered.PKCEChallengeMethod
	replacement.EnableJWTProfileOAuthAccessTokens = registered.EnableJWTProfileOAuthAccessTokens
	replacement.PushedAuthorizeContextLifespan = registered.PushedAuthorizeContextLifespan

	if secret == nil {
		replacement.ClientSecret = registered.ClientSecret
	} else {
		replacement.ClientSecret = secret
	}

	return replacement, nil
}

// MetadataFromClient converts a *oauth2.DefaultRegisteredClient back into its oauth2.ClientRegistrationMetadata
// representation, as returned by the client registration and client configuration endpoints.
func (s *DefaultClientRegistrationStrategy) MetadataFromClient(ctx context.Context, client oauth2.Client) (metadata *oauth2.ClientRegistrationMetadata, err error) {
	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The default client registration strategy can only convert a '*oauth2.DefaultRegisteredClient' but the client with id '%s' is a '%T'.", client.GetID(), client))
	}

	responseModes := make([]string, len(registered.ResponseModes))
	for i, mode := range registered.ResponseModes {
		responseModes[i] = string(mode)
	}

	return &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            registered.RedirectURIs,
		TokenEndpointAuthMethod: registered.TokenEndpointAuthMethod,
		GrantTypes:              registered.GrantTypes,
		ResponseTypes:           registered.ResponseTypes,
		ClientName:              registered.ClientName,
		ClientURI:               registered.ClientURI,
		LogoURI:                 registered.LogoURI,
		Scope:                   strings.Join(registered.Scopes, " "),
		Contacts:                registered.Contacts,
		TOSURI:                  registered.TOSURI,
		PolicyURI:               registered.PolicyURI,
		JSONWebKeysURI:          registered.JSONWebKeysURI,
		JSONWebKeys:             registered.JSONWebKeys,
		SoftwareID:              registered.SoftwareID,
		SoftwareStatement:       registered.SoftwareStatement,
		SoftwareVersion:         registered.SoftwareVersion,

		ApplicationType:              registered.ApplicationType,
		SectorIdentifierURI:          registered.SectorIdentifierURI,
		SubjectType:                  registered.SubjectType,
		IDTokenSignedResponseAlg:     registered.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  registered.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  registered.IDTokenEncryptedResponseEnc,
		UserinfoSignedResponseAlg:    registered.UserinfoSignedResponseAlg,
		UserinfoEncryptedResponseAlg: registered.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: registered.UserinfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      registered.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:   registered.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   registered.RequestObjectEncryptionEnc,
		TokenEndpointAuthSigningAlg:  registered.TokenEndpointAuthSigningAlg,
		DefaultMaxAge:                copyInt64(registered.DefaultMaxAge),
		RequireAuthTime:              registered.RequireAuthTime,
		DefaultACRValues:             registered.DefaultACRValues,
		InitiateLoginURI:             registered.InitiateLoginURI,
		RequestURIs:                  registered.RequestURIs,

		RequireSignedRequestObject: registered.RequireSignedRequestObject,

		PostLogoutRedirectURIs:           registered.PostLogoutRedirectURIs,
		BackChannelLogoutURI:             registered.BackChannelLogoutURI,
		BackChannelLogoutSessionRequired: registered.BackChannelLogoutSessionRequired,

		TLSClientAuthSubjectDN:                registered.TLSClientAuthSubjectDN,
		TLSClientAuthSANDNS:                   registered.TLSClientAuthSANDNS,
		TLSClientAuthSANURI:                   registered.TLSClientAuthSANURI,
		TLSClientAuthSANIP:                    registered.TLSClientAuthSANIP,
		TLSClientAuthSANEmail:                 registered.TLSClientAuthSANEmail,
		TLSClientCertificateBoundAccessTokens: registered.TLSClientCertificateBoundAccessTokens,

		IDTokenSignedResponseKeyID:          registered.IDTokenSignedResponseKeyID,
		IDTokenEncryptedResponseKeyID:       registered.IDTokenEncryptedResponseKeyID,
		UserinfoSignedResponseKeyID:         registered.UserinfoSignedResponseKeyID,
		UserinfoEncryptedResponseKeyID:      registered.UserinfoEncryptedResponseKeyID,
		RequestObjectSigningKeyID:           registered.RequestObjectSigningKeyID,
		RequestObjectEncryptionKeyID:        registered.RequestObjectEncryptionKeyID,
		AuthorizationSignedResponseKeyID:    registered.AuthorizationSignedResponseKeyID,
		AuthorizationSignedResponseAlg:      registered.AuthorizationSignedResponseAlg,
		AuthorizationEncryptedResponseKeyID: registered.AuthorizationEncryptedResponseKeyID,
		AuthorizationEncryptedResponseAlg:   registered.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc:   registered.AuthorizationEncryptedResponseEnc,
		IntrospectionSignedResponseKeyID:    registered.IntrospectionSignedResponseKeyID,
		IntrospectionSignedResponseAlg:      registered.IntrospectionSignedResponseAlg,
		IntrospectionEncryptedResponseKeyID: registered.IntrospectionEncryptedResponseKeyID,
		IntrospectionEncryptedResponseAlg:   registered.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc:   registered.IntrospectionEncryptedResponseEnc,
		AccessTokenSignedResponseKeyID:      registered.AccessTokenSignedResponseKeyID,
		AccessTokenSignedResponseAlg:        registered.AccessTokenSignedResponseAlg,
		AccessTokenEncryptedResponseKeyID:   registered.AccessTokenEncryptedResponseKeyID,
		AccessTokenEncryptedResponseAlg:     registered.AccessTokenEncryptedResponseAlg,
		AccessTokenEncryptedResponseEnc:     registered.AccessTokenEncryptedResponseEnc,
		IntrospectionEndpointAuthMethod:     registered.IntrospectionEndpointAuthMethod,
		IntrospectionEndpointAuthSigningAlg: registered.IntrospectionEndpointAuthSigningAlg,
		RevocationEndpointAuthMethod:        registered.RevocationEndpointAuthMethod,
		RevocationEndpointAuthSigningAlg:    registered.RevocationEndpointAuthSigningAlg,
		RequirePushedAuthorizationRequests:  registered.RequirePushedAuthorizationRequests,
		DPoPBoundAccessTokens:               registered.DPoPBoundAccessTokens,
		ResponseModes:                       responseModes,
		Audience:                            registered.Audience,

		Extra: registered.Extra,
	}, nil
}

// apply assigns every oauth2.ClientRegistrationMetadata field to its corresponding oauth2.DefaultRegisteredClient
// field. It is shared by NewClient and PatchClient so their replacement semantics cannot diverge.
func (s *DefaultClientRegistrationStrategy) apply(registered *oauth2.DefaultRegisteredClient, metadata *oauth2.ClientRegistrationMetadata) {
	registered.RedirectURIs = metadata.RedirectURIs
	registered.TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod

	// Public is derived from the token endpoint authentication method rather than preserved: it is a function of
	// registered metadata, not independent server policy, so a client registering (or later patching) with
	// "none" must be recognized as public.
	registered.Public = metadata.TokenEndpointAuthMethod == consts.ClientAuthMethodNone
	registered.GrantTypes = metadata.GrantTypes
	registered.ResponseTypes = metadata.ResponseTypes
	registered.ClientName = metadata.ClientName
	registered.ClientURI = metadata.ClientURI
	registered.LogoURI = metadata.LogoURI
	registered.Scopes = metadata.GetScopes()
	registered.Contacts = metadata.Contacts
	registered.TOSURI = metadata.TOSURI
	registered.PolicyURI = metadata.PolicyURI
	registered.JSONWebKeysURI = metadata.JSONWebKeysURI
	registered.JSONWebKeys = metadata.JSONWebKeys
	registered.SoftwareID = metadata.SoftwareID
	registered.SoftwareStatement = metadata.SoftwareStatement
	registered.SoftwareVersion = metadata.SoftwareVersion

	registered.ApplicationType = metadata.ApplicationType
	registered.SectorIdentifierURI = metadata.SectorIdentifierURI
	registered.SubjectType = metadata.SubjectType
	registered.IDTokenSignedResponseAlg = metadata.IDTokenSignedResponseAlg
	registered.IDTokenEncryptedResponseAlg = metadata.IDTokenEncryptedResponseAlg
	registered.IDTokenEncryptedResponseEnc = metadata.IDTokenEncryptedResponseEnc
	registered.UserinfoSignedResponseAlg = metadata.UserinfoSignedResponseAlg
	registered.UserinfoEncryptedResponseAlg = metadata.UserinfoEncryptedResponseAlg
	registered.UserinfoEncryptedResponseEnc = metadata.UserinfoEncryptedResponseEnc
	registered.RequestObjectSigningAlg = metadata.RequestObjectSigningAlg
	registered.RequestObjectEncryptionAlg = metadata.RequestObjectEncryptionAlg
	registered.RequestObjectEncryptionEnc = metadata.RequestObjectEncryptionEnc
	registered.TokenEndpointAuthSigningAlg = metadata.TokenEndpointAuthSigningAlg
	registered.DefaultMaxAge = copyInt64(metadata.DefaultMaxAge)
	registered.RequireAuthTime = metadata.RequireAuthTime
	registered.DefaultACRValues = metadata.DefaultACRValues
	registered.InitiateLoginURI = metadata.InitiateLoginURI
	registered.RequestURIs = metadata.RequestURIs

	registered.RequireSignedRequestObject = metadata.RequireSignedRequestObject

	registered.PostLogoutRedirectURIs = metadata.PostLogoutRedirectURIs
	registered.BackChannelLogoutURI = metadata.BackChannelLogoutURI
	registered.BackChannelLogoutSessionRequired = metadata.BackChannelLogoutSessionRequired

	registered.TLSClientAuthSubjectDN = metadata.TLSClientAuthSubjectDN
	registered.TLSClientAuthSANDNS = metadata.TLSClientAuthSANDNS
	registered.TLSClientAuthSANURI = metadata.TLSClientAuthSANURI
	registered.TLSClientAuthSANIP = metadata.TLSClientAuthSANIP
	registered.TLSClientAuthSANEmail = metadata.TLSClientAuthSANEmail
	registered.TLSClientCertificateBoundAccessTokens = metadata.TLSClientCertificateBoundAccessTokens

	registered.IDTokenSignedResponseKeyID = metadata.IDTokenSignedResponseKeyID
	registered.IDTokenEncryptedResponseKeyID = metadata.IDTokenEncryptedResponseKeyID
	registered.UserinfoSignedResponseKeyID = metadata.UserinfoSignedResponseKeyID
	registered.UserinfoEncryptedResponseKeyID = metadata.UserinfoEncryptedResponseKeyID
	registered.RequestObjectSigningKeyID = metadata.RequestObjectSigningKeyID
	registered.RequestObjectEncryptionKeyID = metadata.RequestObjectEncryptionKeyID
	registered.AuthorizationSignedResponseKeyID = metadata.AuthorizationSignedResponseKeyID
	registered.AuthorizationSignedResponseAlg = metadata.AuthorizationSignedResponseAlg
	registered.AuthorizationEncryptedResponseKeyID = metadata.AuthorizationEncryptedResponseKeyID
	registered.AuthorizationEncryptedResponseAlg = metadata.AuthorizationEncryptedResponseAlg
	registered.AuthorizationEncryptedResponseEnc = metadata.AuthorizationEncryptedResponseEnc
	registered.IntrospectionSignedResponseKeyID = metadata.IntrospectionSignedResponseKeyID
	registered.IntrospectionSignedResponseAlg = metadata.IntrospectionSignedResponseAlg
	registered.IntrospectionEncryptedResponseKeyID = metadata.IntrospectionEncryptedResponseKeyID
	registered.IntrospectionEncryptedResponseAlg = metadata.IntrospectionEncryptedResponseAlg
	registered.IntrospectionEncryptedResponseEnc = metadata.IntrospectionEncryptedResponseEnc
	registered.AccessTokenSignedResponseKeyID = metadata.AccessTokenSignedResponseKeyID
	registered.AccessTokenSignedResponseAlg = metadata.AccessTokenSignedResponseAlg
	registered.AccessTokenEncryptedResponseKeyID = metadata.AccessTokenEncryptedResponseKeyID
	registered.AccessTokenEncryptedResponseAlg = metadata.AccessTokenEncryptedResponseAlg
	registered.AccessTokenEncryptedResponseEnc = metadata.AccessTokenEncryptedResponseEnc
	registered.IntrospectionEndpointAuthMethod = metadata.IntrospectionEndpointAuthMethod
	registered.IntrospectionEndpointAuthSigningAlg = metadata.IntrospectionEndpointAuthSigningAlg
	registered.RevocationEndpointAuthMethod = metadata.RevocationEndpointAuthMethod
	registered.RevocationEndpointAuthSigningAlg = metadata.RevocationEndpointAuthSigningAlg
	registered.RequirePushedAuthorizationRequests = metadata.RequirePushedAuthorizationRequests
	registered.DPoPBoundAccessTokens = metadata.DPoPBoundAccessTokens
	registered.Audience = metadata.Audience

	registered.ResponseModes = make([]oauth2.ResponseModeType, len(metadata.ResponseModes))
	for i, mode := range metadata.ResponseModes {
		registered.ResponseModes[i] = oauth2.ResponseModeType(mode)
	}

	registered.Extra = metadata.Extra
}

// copyInt64 returns a distinct pointer to the same value, or nil for nil. Optional numeric client metadata is carried
// by pointer so an explicitly registered zero stays distinguishable from an absent value; assigning the pointer
// itself across the metadata/client boundary would leave request-owned metadata and the persisted client sharing one
// int64, so a later write through either would be visible through the other.
func copyInt64(value *int64) (copied *int64) {
	if value == nil {
		return nil
	}

	copied = new(int64)
	*copied = *value

	return copied
}

var (
	_ oauth2.ClientRegistrationStrategy = (*DefaultClientRegistrationStrategy)(nil)
)
