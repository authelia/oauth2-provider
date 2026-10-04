// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type MemoryUserRelation struct {
	Username string
	Password string
}

type IssuerPublicKeys struct {
	Issuer    string
	KeysBySub map[string]SubjectPublicKeys
}

type SubjectPublicKeys struct {
	Subject string
	Keys    map[string]PublicKeyScopes
}

type PublicKeyScopes struct {
	Key      *jose.JSONWebKey
	Scopes   []string
	Audience []string
}

// DPoPProofMarker identifies a used DPoP proof for replay detection. It follows the RFC 9449 Section 11.1
// recommendation to store the 'jti' "in the context of the target URI", taking that context to be the endpoint the
// proof is bound to: the method as well as the normalized target URI, since RFC 9449 Section 4.3 binds a proof to both
// and the two together are what identifies an endpoint.
//
// rfc9449.DPoPReplayStorage passes the proof key thumbprint and nonce as well, and documents why an implementation may
// prefer to include them: keying without the thumbprint leaves the 'jti' namespace shared by every client, so one
// client emitting weak 'jti' values denies service to every other client that happens to pick the same value. A
// deployment for which that matters should key on those fields too rather than use this store.
type DPoPProofMarker struct {
	JTI    string
	Method string
	URL    string
}

// JTIMarker identifies a used JWT for replay detection. RFC 7519 Section 4.1.7 only requires a 'jti' to be unique
// among the JWTs produced by one issuer, so a 'jti' is known only in the context of the issuer that produced it. For a
// client assertion the issuer is the client, as RFC 7521 Section 5.2 and OpenID Connect Core 1.0 Section 9 require the
// 'iss' claim to be the client_id.
type JTIMarker struct {
	Issuer string
	JTI    string
}

// IDJAGRelationshipKey identifies an ID-JAG relationship by requesting client and requested audience.
type IDJAGRelationshipKey struct {
	ClientID string
	Audience string
}

// IDJAGSubjectKey identifies an ID-JAG subject within the namespace of its issuer, and of its tenant when the issuer
// is multi-tenant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1
type IDJAGSubjectKey struct {
	// Issuer is the 'iss' claim of the grant.
	Issuer string

	// Tenant is the 'tenant' claim of the grant, empty when the grant has none. A grant whose 'tenant' claim is
	// present but empty or not a string is not resolved.
	Tenant string

	// Subject is the 'sub' claim of the grant.
	Subject string
}

// MemoryStore is a reference storage implementation which keeps every record in memory. It is intended for tests and
// examples rather than production use.
//
// The used 'jti' values are kept in a separate map per purpose: ClientAssertionJTIs for client assertions,
// RFC7523JTIs for RFC 7523 authorization grants, TokenExchangeJTIs for RFC 8693 custom JWT subject and actor
// tokens, and IDJAGJTIs for ID-JAG redemptions. Expired 'jti' values, DPoP proof markers and DPoP nonces are no
// longer recognised once they expire, and are removed by the next insert into the same map once the prune interval
// has elapsed.
//
// AccessTokenRequestIDs indexes every access token signature issued for a request ID, as one request may own several
// live access tokens (e.g. the OpenID Connect hybrid flow).
type MemoryStore struct {
	Clients                  map[string]oauth2.Client
	AuthorizeCodes           map[string]StoreAuthorizeCode
	IDSessions               map[string]oauth2.Requester
	AccessTokens             map[string]oauth2.Requester
	ClientRegistrationTokens map[string]oauth2.Requester
	RefreshTokens            map[string]StoreRefreshToken
	DeviceCodes              map[string]oauth2.Requester
	UserCodes                map[string]oauth2.Requester
	InvalidatedDeviceCodes   map[string]bool
	PKCES                    map[string]oauth2.Requester
	Users                    map[string]MemoryUserRelation
	ClientAssertionJTIs      map[JTIMarker]time.Time
	RFC7523JTIs              map[JTIMarker]time.Time
	TokenExchangeJTIs        map[JTIMarker]time.Time
	AccessTokenRequestIDs    map[string]map[string]struct{}
	RefreshTokenRequestIDs   map[string]string
	IssuerPublicKeys         map[string]IssuerPublicKeys
	PARSessions              map[string]oauth2.AuthorizeRequester
	DPoPProofJTIs            map[DPoPProofMarker]time.Time
	DPoPNonces               map[string]time.Time
	IDJAGRelationships       map[IDJAGRelationshipKey]oauth2.IDJAGRelationship
	IDJAGTrustedIssuers      map[string]oauth2.IDJAGTrustedIssuer
	IDJAGSubjects            map[IDJAGSubjectKey]string
	IDJAGJTIs                map[JTIMarker]time.Time

	clientsMutex                  sync.RWMutex
	authorizeCodesMutex           sync.RWMutex
	idSessionsMutex               sync.RWMutex
	accessTokensMutex             sync.RWMutex
	clientRegistrationTokensMutex sync.RWMutex
	refreshTokensMutex            sync.RWMutex
	deviceCodesMutex              sync.RWMutex
	pkcesMutex                    sync.RWMutex
	usersMutex                    sync.RWMutex
	jtisMutex                     sync.RWMutex
	accessTokenRequestIDsMutex    sync.RWMutex
	refreshTokenRequestIDsMutex   sync.RWMutex
	issuerPublicKeysMutex         sync.RWMutex
	parSessionsMutex              sync.RWMutex
	dpopProofJTIsMutex            sync.RWMutex
	dpopNoncesMutex               sync.RWMutex
	idjagMutex                    sync.RWMutex

	clientAssertionJTIsPruneAt time.Time
	rfc7523JTIsPruneAt         time.Time
	tokenExchangeJTIsPruneAt   time.Time
	dpopProofJTIsPruneAt       time.Time
	dpopNoncesPruneAt          time.Time
	idjagJTIsPruneAt           time.Time
}

const memoryStorePruneInterval = time.Minute

// NewMemoryStore returns a new *MemoryStore with every map initialized.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:                  make(map[string]oauth2.Client),
		AuthorizeCodes:           make(map[string]StoreAuthorizeCode),
		IDSessions:               make(map[string]oauth2.Requester),
		AccessTokens:             make(map[string]oauth2.Requester),
		ClientRegistrationTokens: make(map[string]oauth2.Requester),
		RefreshTokens:            make(map[string]StoreRefreshToken),
		DeviceCodes:              make(map[string]oauth2.Requester),
		UserCodes:                make(map[string]oauth2.Requester),
		InvalidatedDeviceCodes:   make(map[string]bool),
		PKCES:                    make(map[string]oauth2.Requester),
		Users:                    make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:    make(map[string]map[string]struct{}),
		RefreshTokenRequestIDs:   make(map[string]string),
		ClientAssertionJTIs:      make(map[JTIMarker]time.Time),
		RFC7523JTIs:              make(map[JTIMarker]time.Time),
		TokenExchangeJTIs:        make(map[JTIMarker]time.Time),
		IssuerPublicKeys:         make(map[string]IssuerPublicKeys),
		PARSessions:              make(map[string]oauth2.AuthorizeRequester),
		DPoPProofJTIs:            make(map[DPoPProofMarker]time.Time),
		DPoPNonces:               make(map[string]time.Time),
		IDJAGRelationships:       make(map[IDJAGRelationshipKey]oauth2.IDJAGRelationship),
		IDJAGTrustedIssuers:      make(map[string]oauth2.IDJAGTrustedIssuer),
		IDJAGSubjects:            make(map[IDJAGSubjectKey]string),
		IDJAGJTIs:                make(map[JTIMarker]time.Time),
	}
}

type StoreAuthorizeCode struct {
	active bool
	oauth2.Requester
}

type StoreRefreshToken struct {
	active               bool
	accessTokenSignature string
	oauth2.Requester
}

// NewExampleStore returns a new *MemoryStore populated with example clients and an example user.
func NewExampleStore() *MemoryStore {
	store := NewMemoryStore()

	example := &MemoryStore{
		Clients: map[string]oauth2.Client{
			"my-client": &oauth2.DefaultClient{
				ID:                   "my-client",
				ClientSecret:         oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),                        // = "foobar"
				RotatedClientSecrets: []oauth2.ClientSecret{oauth2.NewBCryptClientSecret(`$2a$04$4X4/mCFdQ9tmfjSBBk6RNOhg0MtKE0ql7BPyMHDuiuq7YeY6wGlh.`)}, // = "foobaz"
				RedirectURIs:         []string{"http://localhost:3846/callback"},
				ResponseTypes:        []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:           []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
				Scopes:               []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
			},
			"custom-lifespan-client": &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient: &oauth2.DefaultClient{
					ID:                   "custom-lifespan-client",
					ClientSecret:         oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),                        // = "foobar"
					RotatedClientSecrets: []oauth2.ClientSecret{oauth2.NewBCryptClientSecret(`$2a$04$4X4/mCFdQ9tmfjSBBk6RNOhg0MtKE0ql7BPyMHDuiuq7YeY6wGlh.`)}, // = "foobaz"
					RedirectURIs:         []string{"http://localhost:3846/callback"},
					ResponseTypes:        []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
					GrantTypes:           []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
					Scopes:               []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
				},
				TokenLifespans: exampleLifespans(),
			},
			"encoded:client": &oauth2.DefaultClient{
				ID:                   "encoded:client",
				ClientSecret:         oauth2.NewBCryptClientSecret(`$2a$04$8FzF6Ig9KHbTD8Q4VLOb5eIH8vbg.Lz3TXb2vAkDeP/XEDHmqCHGi`), // = "encoded&password"
				RotatedClientSecrets: nil,
				RedirectURIs:         []string{"http://localhost:3846/callback"},
				ResponseTypes:        []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:           []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:               []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
			},
		},
		Users: map[string]MemoryUserRelation{
			"peter": {
				// This store simply checks for equality, a real storage implementation would obviously use
				// a hashing algorithm for encrypting the user password.
				Username: "peter",
				Password: "secret",
			},
		},
	}

	store.Clients, store.Users = example.Clients, example.Users

	return store
}

func exampleLifespans() *oauth2.ClientLifespanConfig {
	ptr := func(d time.Duration) *time.Duration {
		return &d
	}

	return &oauth2.ClientLifespanConfig{
		AuthorizationCodeGrantAccessTokenLifespan:  ptr(31 * time.Hour),
		AuthorizationCodeGrantIDTokenLifespan:      ptr(32 * time.Hour),
		AuthorizationCodeGrantRefreshTokenLifespan: ptr(33 * time.Hour),
		ClientCredentialsGrantAccessTokenLifespan:  ptr(34 * time.Hour),
		ImplicitGrantAccessTokenLifespan:           ptr(35 * time.Hour),
		ImplicitGrantIDTokenLifespan:               ptr(36 * time.Hour),
		JwtBearerGrantAccessTokenLifespan:          ptr(37 * time.Hour),
		PasswordGrantAccessTokenLifespan:           ptr(38 * time.Hour),
		PasswordGrantRefreshTokenLifespan:          ptr(39 * time.Hour),
		RefreshTokenGrantIDTokenLifespan:           ptr(40 * time.Hour),
		RefreshTokenGrantAccessTokenLifespan:       ptr(41 * time.Hour),
		RefreshTokenGrantRefreshTokenLifespan:      ptr(42 * time.Hour),
		TokenExchangeGrantAccessTokenLifespan:      ptr(43 * time.Hour),
		TokenExchangeGrantRefreshTokenLifespan:     ptr(44 * time.Hour),
	}
}

// CreateOpenIDConnectSession stores the request against the authorization code.
func (s *MemoryStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, request oauth2.Requester) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	s.IDSessions[authorizeCode] = request
	return nil
}

// GetOpenIDConnectSession returns the request stored against the authorization code, or oauth2.ErrNotFound when no
// session exists for it.
func (s *MemoryStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, request oauth2.Requester) (oauth2.Requester, error) {
	s.idSessionsMutex.RLock()
	defer s.idSessionsMutex.RUnlock()

	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return cl, nil
}

// DeleteOpenIDConnectSession is not really called from anywhere and it is deprecated.
func (s *MemoryStore) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	delete(s.IDSessions, authorizeCode)
	return nil
}

// GetClient returns the client with the given id, or oauth2.ErrNotFound when no such client exists.
func (s *MemoryStore) GetClient(_ context.Context, id string) (oauth2.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.Clients[id]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return cl, nil
}

// CreateClient stores the client, returning an error when a client with the same id already exists.
func (s *MemoryStore) CreateClient(_ context.Context, client oauth2.Client) (err error) {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	id := client.GetID()

	if _, ok := s.Clients[id]; ok {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("Client with id '%s' already exists.", id))
	}

	s.Clients[id] = client

	return nil
}

// UpdateClient replaces the client stored with the given id. It returns an error when no such client exists, or when
// the id of the given client differs from id.
func (s *MemoryStore) UpdateClient(_ context.Context, id string, client oauth2.Client) (err error) {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	if _, ok := s.Clients[id]; !ok {
		return errorsx.WithStack(oauth2.ErrNotFound.WithHintf("No client with id '%s' was found.", id))
	}

	// The id argument and the client's own id must agree, otherwise the client stored under this key would answer
	// GetClient with a client that reports a different id - and every later lookup keyed off that reported id would
	// miss it, or worse, find a different client.
	if client.GetID() != id {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The client with id '%s' can not be updated with a client with id '%s'.", id, client.GetID()))
	}

	s.Clients[id] = client

	return nil
}

// DeleteClient removes the client with the given id, returning an error when no such client exists.
func (s *MemoryStore) DeleteClient(_ context.Context, id string) (err error) {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	if _, ok := s.Clients[id]; !ok {
		return errorsx.WithStack(oauth2.ErrNotFound.WithHintf("No client with id '%s' was found.", id))
	}

	delete(s.Clients, id)

	return nil
}

// SetTokenLifespans replaces the stored client with a copy that has the given lifespans. A client already returned by
// GetClient is not modified.
func (s *MemoryStore) SetTokenLifespans(clientID string, lifespans *oauth2.ClientLifespanConfig) error {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	if client, ok := s.Clients[clientID]; ok {
		if clc, ok := client.(*oauth2.DefaultClientWithCustomTokenLifespans); ok {
			updated := *clc
			updated.SetTokenLifespans(lifespans)

			s.Clients[clientID] = &updated

			return nil
		}

		return oauth2.ErrorToRFC6749Error(errors.New("failed to set token lifespans due to failed client type assertion"))
	}

	return oauth2.ErrNotFound
}

// ClientAssertionJWTValid returns oauth2.ErrJTIKnown when the client has already used the 'jti' in an unexpired client
// assertion. The 'jti' is scoped to the client per RFC 7519 Section 4.1.7, see JTIMarker.
func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, clientID, jti string) error {
	return s.isJTIKnown(s.ClientAssertionJTIs, JTIMarker{Issuer: clientID, JTI: jti})
}

// SetClientAssertionJWT marks the 'jti' as used by the client until exp, returning oauth2.ErrJTIKnown when it is
// already marked. The 'jti' is scoped to the client per RFC 7519 Section 4.1.7, see JTIMarker.
func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, clientID, jti string, exp time.Time) error {
	return s.setJTI(s.ClientAssertionJTIs, &s.clientAssertionJTIsPruneAt, JTIMarker{Issuer: clientID, JTI: jti}, exp)
}

func (s *MemoryStore) isJTIKnown(jtis map[JTIMarker]time.Time, marker JTIMarker) error {
	s.jtisMutex.RLock()
	defer s.jtisMutex.RUnlock()

	if exp, exists := jtis[marker]; exists && exp.After(time.Now()) {
		return oauth2.ErrJTIKnown
	}

	return nil
}

func (s *MemoryStore) setJTI(jtis map[JTIMarker]time.Time, pruneAt *time.Time, marker JTIMarker, exp time.Time) error {
	s.jtisMutex.Lock()
	defer s.jtisMutex.Unlock()

	now := time.Now()

	pruneExpired(jtis, pruneAt, now)

	if e, exists := jtis[marker]; exists && !e.Before(now) {
		return oauth2.ErrJTIKnown
	}

	jtis[marker] = exp

	return nil
}

func pruneExpired[K comparable](entries map[K]time.Time, pruneAt *time.Time, now time.Time) {
	if now.Before(*pruneAt) {
		return
	}

	*pruneAt = now.Add(memoryStorePruneInterval)

	for key, exp := range entries {
		if exp.Before(now) {
			delete(entries, key)
		}
	}
}

// CreateAuthorizeCodeSession stores the request against the authorization code as an active code.
func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req oauth2.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

// GetAuthorizeCodeSession returns the request stored against the authorization code, or oauth2.ErrNotFound when no
// session exists for it. When the code has been invalidated it returns the request alongside
// oauth2.ErrInvalidatedAuthorizeCode.
func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ oauth2.Session) (oauth2.Requester, error) {
	s.authorizeCodesMutex.RLock()
	defer s.authorizeCodesMutex.RUnlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	if !rel.active {
		return rel, oauth2.ErrInvalidatedAuthorizeCode
	}

	return rel.Requester, nil
}

// InvalidateAuthorizeCodeSession marks the authorization code as invalidated. It returns oauth2.ErrNotFound when no
// session exists for the code, and oauth2.ErrInvalidatedAuthorizeCode when the code is already invalidated.
func (s *MemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return oauth2.ErrNotFound
	}

	if !rel.active {
		return oauth2.ErrInvalidatedAuthorizeCode
	}

	rel.active = false

	s.AuthorizeCodes[code] = rel

	return nil
}

// CreatePKCERequestSession stores the PKCE request against the authorization code.
func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req oauth2.Requester) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	s.PKCES[code] = req
	return nil
}

// GetPKCERequestSession returns the PKCE request stored against the authorization code, or oauth2.ErrNotFound when no
// session exists for it.
func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ oauth2.Session) (oauth2.Requester, error) {
	s.pkcesMutex.RLock()
	defer s.pkcesMutex.RUnlock()

	rel, ok := s.PKCES[code]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return rel, nil
}

// DeletePKCERequestSession removes the PKCE request stored against the authorization code. Deleting a code that has no
// session is not an error.
func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	delete(s.PKCES, code)
	return nil
}

// CreateAccessTokenSession stores the request against the access token signature and adds the signature to those
// recorded against the request ID so RevokeAccessToken can find every access token issued for the request.
func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req oauth2.Requester) error {
	// We first lock accessTokenRequestIDsMutex and then accessTokensMutex because this is the same order
	// locking happens in RevokeAccessToken and using the same order prevents deadlocks.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	s.AccessTokens[signature] = req

	signatures, ok := s.AccessTokenRequestIDs[req.GetID()]
	if !ok {
		signatures = make(map[string]struct{})
		s.AccessTokenRequestIDs[req.GetID()] = signatures
	}

	signatures[signature] = struct{}{}

	return nil
}

// GetAccessTokenSession returns the request stored against the access token signature, or oauth2.ErrNotFound when no
// session exists for it.
func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ oauth2.Session) (oauth2.Requester, error) {
	s.accessTokensMutex.RLock()
	defer s.accessTokensMutex.RUnlock()

	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return rel, nil
}

// DeleteAccessTokenSession removes the session stored against the access token signature. Deleting a signature that
// has no session is not an error.
func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	if req, ok := s.AccessTokens[signature]; ok {
		if signatures, ok := s.AccessTokenRequestIDs[req.GetID()]; ok {
			delete(signatures, signature)

			if len(signatures) == 0 {
				delete(s.AccessTokenRequestIDs, req.GetID())
			}
		}
	}

	delete(s.AccessTokens, signature)

	return nil
}

// CreateClientRegistrationTokenSession stores the request against the client registration token signature, in a
// namespace separate from access tokens.
func (s *MemoryStore) CreateClientRegistrationTokenSession(_ context.Context, signature string, req oauth2.Requester) error {
	s.clientRegistrationTokensMutex.Lock()
	defer s.clientRegistrationTokensMutex.Unlock()

	s.ClientRegistrationTokens[signature] = req

	return nil
}

// GetClientRegistrationTokenSession returns the request stored against the client registration token signature.
func (s *MemoryStore) GetClientRegistrationTokenSession(_ context.Context, signature string, _ oauth2.Session) (oauth2.Requester, error) {
	s.clientRegistrationTokensMutex.RLock()
	defer s.clientRegistrationTokensMutex.RUnlock()

	rel, ok := s.ClientRegistrationTokens[signature]
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	return rel, nil
}

// DeleteClientRegistrationTokenSession removes the session stored against the client registration token signature.
func (s *MemoryStore) DeleteClientRegistrationTokenSession(_ context.Context, signature string) error {
	s.clientRegistrationTokensMutex.Lock()
	defer s.clientRegistrationTokensMutex.Unlock()

	delete(s.ClientRegistrationTokens, signature)

	return nil
}

// CreateRefreshTokenSession stores the request against the refresh token signature as an active token, retaining the
// signature of the access token issued alongside it, and records the signature against the request ID so
// RevokeRefreshToken and RotateRefreshToken can find it later.
func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature, accessTokenSignature string, req oauth2.Requester) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in RevokeRefreshToken and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	s.RefreshTokens[signature] = StoreRefreshToken{active: true, accessTokenSignature: accessTokenSignature, Requester: req}
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	return nil
}

// GetRefreshTokenSession returns the request stored against the refresh token signature, or oauth2.ErrNotFound when no
// session exists for it. When the refresh token has been deactivated it returns the request alongside
// oauth2.ErrInactiveToken so the refresh token grant handler can revoke the rest of the authorization grant.
func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ oauth2.Session) (oauth2.Requester, error) {
	s.refreshTokensMutex.RLock()
	defer s.refreshTokensMutex.RUnlock()

	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	if !rel.active {
		return rel, oauth2.ErrInactiveToken
	}
	return rel, nil
}

// UpdateRefreshTokenSession replaces the request stored against the refresh token signature, keeping its active state
// and the signature of the access token issued alongside it. It returns oauth2.ErrNotFound when no session exists for
// the signature.
func (s *MemoryStore) UpdateRefreshTokenSession(_ context.Context, signature string, req oauth2.Requester) error {
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return oauth2.ErrNotFound
	}

	rel.Requester = req
	s.RefreshTokens[signature] = rel

	return nil
}

// DeleteRefreshTokenSession removes the session stored against the refresh token signature. Deleting a signature that
// has no session is not an error.
func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	delete(s.RefreshTokens, signature)
	return nil
}

// Authenticate compares the secret to the password stored for the user and returns a new random identifier when they
// match. It returns oauth2.ErrNotFound when the user does not exist or the secret does not match.
func (s *MemoryStore) Authenticate(ctx context.Context, name string, secret string) (string, error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	rel, ok := s.Users[name]
	if !ok {
		return "", oauth2.ErrNotFound
	}

	if rel.Password != secret {
		return "", oauth2.ErrNotFound.WithDebug("Invalid credentials.")
	}

	return uuid.New().String(), nil
}

// RevokeRefreshToken deactivates the refresh token recorded against the request ID. A request ID with no recorded
// refresh token is not an error.
func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()

	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	return s.deactivateRefreshToken(requestID)
}

func (s *MemoryStore) deactivateRefreshToken(requestID string) error {
	if signature, exists := s.RefreshTokenRequestIDs[requestID]; exists {
		rel, ok := s.RefreshTokens[signature]
		if !ok {
			return oauth2.ErrNotFound
		}
		rel.active = false
		s.RefreshTokens[signature] = rel
	}
	return nil
}

// RotateRefreshToken deactivates the refresh token and revokes the access tokens issued for the same request, which
// the request ID locates. It returns oauth2.ErrInactiveToken when the refresh token with the given signature is
// already inactive, as it is when a concurrent request rotated it first. A grace period is not implemented by the
// memory store; implementations that need one should mark the refresh token as expiring after the grace period instead
// of deactivating it here.
func (s *MemoryStore) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	if err := s.rotateRefreshToken(requestID, signature); err != nil {
		return err
	}

	return s.RevokeAccessToken(ctx, requestID)
}

func (s *MemoryStore) rotateRefreshToken(requestID, signature string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()

	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	if rel, exists := s.RefreshTokens[signature]; exists && !rel.active {
		return oauth2.ErrInactiveToken
	}

	return s.deactivateRefreshToken(requestID)
}

// RevokeAccessToken removes every access token issued for the request ID. RFC 7009 Section 2.1 requires revoking a
// refresh token to invalidate all access tokens based on the same authorization grant, and one request ID may own
// several of them.
func (s *MemoryStore) RevokeAccessToken(_ context.Context, requestID string) error {
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	for signature := range s.AccessTokenRequestIDs[requestID] {
		delete(s.AccessTokens, signature)
	}

	delete(s.AccessTokenRequestIDs, requestID)

	return nil
}

// GetRFC7523PublicKey returns the public key registered for the issuer, subject and key ID, or oauth2.ErrNotFound when
// none is registered.
func (s *MemoryStore) GetRFC7523PublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Key, nil
			}
		}
	}

	return nil, oauth2.ErrNotFound
}

// GetRFC7523PublicKeys returns every public key registered for the issuer and subject, or oauth2.ErrNotFound when none
// is registered.
func (s *MemoryStore) GetRFC7523PublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if len(subKeys.Keys) == 0 {
				return nil, oauth2.ErrNotFound
			}

			keys := make([]jose.JSONWebKey, 0, len(subKeys.Keys))
			for _, keyScopes := range subKeys.Keys {
				keys = append(keys, *keyScopes.Key)
			}

			return &jose.JSONWebKeySet{Keys: keys}, nil
		}
	}

	return nil, oauth2.ErrNotFound
}

// GetRFC7523PublicKeyScopes returns the scopes registered with the public key for the issuer, subject and key ID, or
// oauth2.ErrNotFound when no such key is registered.
func (s *MemoryStore) GetRFC7523PublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Scopes, nil
			}
		}
	}

	return nil, oauth2.ErrNotFound
}

// GetRFC7523PublicKeyAudience returns the audience registered for the public key of the issuer and subject, which is
// the audience an assertion signed by that key may request.
func (s *MemoryStore) GetRFC7523PublicKeyAudience(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Audience, nil
			}
		}
	}

	return nil, oauth2.ErrNotFound
}

// IsRFC7523JWTUsed reports whether the issuer has already used the 'jti' in an unexpired RFC 7523 authorization grant.
// The 'jti' is scoped to the issuer per RFC 7519 Section 4.1.7, see JTIMarker.
func (s *MemoryStore) IsRFC7523JWTUsed(_ context.Context, issuer, jti string) (bool, error) {
	return s.isJTIKnown(s.RFC7523JTIs, JTIMarker{Issuer: issuer, JTI: jti}) != nil, nil
}

// MarkRFC7523JWTUsedForTime marks the issuer's 'jti' as used until exp, returning oauth2.ErrJTIKnown when it is
// already marked. The 'jti' is scoped to the issuer per RFC 7519 Section 4.1.7, see JTIMarker.
func (s *MemoryStore) MarkRFC7523JWTUsedForTime(_ context.Context, issuer, jti string, exp time.Time) error {
	return s.setJTI(s.RFC7523JTIs, &s.rfc7523JTIsPruneAt, JTIMarker{Issuer: issuer, JTI: jti}, exp)
}

// GetIDJAGRelationship returns a copy of the relationship registered for the client and audience.
func (s *MemoryStore) GetIDJAGRelationship(_ context.Context, request oauth2.AccessRequester, audience string) (*oauth2.IDJAGRelationship, error) {
	s.idjagMutex.RLock()
	defer s.idjagMutex.RUnlock()

	relationship, ok := s.IDJAGRelationships[IDJAGRelationshipKey{ClientID: request.GetClient().GetID(), Audience: audience}]
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	relationship.Scopes = slices.Clone(relationship.Scopes)
	relationship.Resources = slices.Clone(relationship.Resources)
	relationship.AuthorizationDetailsTypes = slices.Clone(relationship.AuthorizationDetailsTypes)

	return &relationship, nil
}

// GetIDJAGTrustedIssuer returns a copy of the trust configuration registered for the issuer.
func (s *MemoryStore) GetIDJAGTrustedIssuer(_ context.Context, issuer string) (*oauth2.IDJAGTrustedIssuer, error) {
	s.idjagMutex.RLock()
	defer s.idjagMutex.RUnlock()

	trusted, ok := s.IDJAGTrustedIssuers[issuer]
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	trusted.SigningAlgs = slices.Clone(trusted.SigningAlgs)
	trusted.Clients = slices.Clone(trusted.Clients)

	if trusted.JSONWebKeys != nil {
		trusted.JSONWebKeys = &jose.JSONWebKeySet{Keys: slices.Clone(trusted.JSONWebKeys.Keys)}
	}

	return &trusted, nil
}

// ResolveIDJAGSubject returns the subject registered for the grant's issuer, tenant and subject, or oauth2.ErrNotFound
// when none is registered.
func (s *MemoryStore) ResolveIDJAGSubject(_ context.Context, _ oauth2.Client, claims map[string]any) (string, error) {
	issuer, _ := claims[consts.ClaimIssuer].(string)
	subject, _ := claims[consts.ClaimSubject].(string)

	if subject == "" {
		return "", oauth2.ErrNotFound
	}

	var tenant string

	if value, ok := claims[consts.ClaimTenant]; ok {
		if tenant, ok = value.(string); !ok || tenant == "" {
			return "", oauth2.ErrNotFound
		}
	}

	s.idjagMutex.RLock()
	defer s.idjagMutex.RUnlock()

	if resolved, ok := s.IDJAGSubjects[IDJAGSubjectKey{Issuer: issuer, Tenant: tenant, Subject: subject}]; ok {
		return resolved, nil
	}

	return "", oauth2.ErrNotFound
}

// IsIDJAGUsed reports whether the issuer's 'jti' was already redeemed and is unexpired.
func (s *MemoryStore) IsIDJAGUsed(_ context.Context, issuer, jti string) (bool, error) {
	return s.isJTIKnown(s.IDJAGJTIs, JTIMarker{Issuer: issuer, JTI: jti}) != nil, nil
}

// MarkIDJAGUsed marks the issuer's 'jti' as redeemed until exp, returning oauth2.ErrJTIKnown when it is already marked.
func (s *MemoryStore) MarkIDJAGUsed(_ context.Context, issuer, jti string, exp time.Time) error {
	return s.setJTI(s.IDJAGJTIs, &s.idjagJTIsPruneAt, JTIMarker{Issuer: issuer, JTI: jti}, exp)
}

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
func (s *MemoryStore) CreatePARSession(ctx context.Context, requestURI string, request oauth2.AuthorizeRequester) error {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	s.PARSessions[requestURI] = request

	return nil
}

// GetPARSession gets the push authorization request context. If the request is nil, a new request object
// is created. Otherwise, the same object is updated.
func (s *MemoryStore) GetPARSession(ctx context.Context, requestURI string) (oauth2.AuthorizeRequester, error) {
	s.parSessionsMutex.RLock()
	defer s.parSessionsMutex.RUnlock()

	r, ok := s.PARSessions[requestURI]
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	return r, nil
}

// DeletePARSession deletes the context. It returns oauth2.ErrNotFound if the context does not exist, so a request_uri
// is only consumed once per RFC 9126 Section 4.
//
// See: https://datatracker.ietf.org/doc/html/rfc9126#section-4
func (s *MemoryStore) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	if _, ok := s.PARSessions[requestURI]; !ok {
		return oauth2.ErrNotFound
	}

	delete(s.PARSessions, requestURI)

	return nil
}

// SetTokenExchangeCustomJWT marks the issuer's 'jti' as used until exp, returning oauth2.ErrJTIKnown when it is
// already marked. The 'jti' is scoped to the issuer per RFC 7519 Section 4.1.7, see JTIMarker.
func (s *MemoryStore) SetTokenExchangeCustomJWT(_ context.Context, issuer, jti string, exp time.Time) error {
	return s.setJTI(s.TokenExchangeJTIs, &s.tokenExchangeJTIsPruneAt, JTIMarker{Issuer: issuer, JTI: jti}, exp)
}

// GetSubjectForTokenExchange computes the session subject and is used for token types where there is no way
// to know the subject value. For some token types, such as access and refresh tokens, the subject is well-defined
// and this function is not called.
func (s *MemoryStore) GetSubjectForTokenExchange(ctx context.Context, request oauth2.Requester, subjectToken map[string]any) (string, error) {
	sub, _ := subjectToken["subject"].(string)
	if sub == "" {
		return "", oauth2.ErrInvalidRequest.WithHint("No subject found.")
	}

	return sub, nil
}

// CreateDeviceCodeSession stores the request against its device code signature and its user code signature. It returns
// oauth2.ErrDuplicateUserCode when the user code signature is already in use.
func (s *MemoryStore) CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	s.deviceCodesMutex.Lock()
	defer s.deviceCodesMutex.Unlock()

	if _, exists := s.UserCodes[request.GetUserCodeSignature()]; exists {
		return oauth2.ErrDuplicateUserCode
	}

	s.DeviceCodes[request.GetDeviceCodeSignature()] = request
	s.UserCodes[request.GetUserCodeSignature()] = request

	return nil
}

// UpdateDeviceCodeSession replaces the request stored against the device code signature, and against the user code
// signature of the request. It does nothing when no session exists for the device code signature.
func (s *MemoryStore) UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	s.deviceCodesMutex.Lock()
	defer s.deviceCodesMutex.Unlock()

	// Only update if exist
	if _, exists := s.DeviceCodes[signature]; exists {
		s.DeviceCodes[signature] = request
		s.UserCodes[request.GetUserCodeSignature()] = request
	}

	return nil
}

// DecideDeviceCodeSession implements rfc8628.DecisionStorage.
func (s *MemoryStore) DecideDeviceCodeSession(_ context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	s.deviceCodesMutex.Lock()
	defer s.deviceCodesMutex.Unlock()

	stored, ok := s.DeviceCodes[signature].(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return oauth2.ErrNotFound
	}

	if stored.GetStatus() != oauth2.DeviceAuthorizeStatusNew {
		return oauth2.ErrDeviceAuthorizeDecided
	}

	s.DeviceCodes[signature] = request
	s.UserCodes[request.GetUserCodeSignature()] = request

	return nil
}

// GetDeviceCodeSession returns the request stored against the device code signature, or oauth2.ErrNotFound when no
// session exists for it. When the device code has been invalidated it returns the request alongside
// oauth2.ErrInvalidatedDeviceCode.
func (s *MemoryStore) GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	s.deviceCodesMutex.RLock()
	defer s.deviceCodesMutex.RUnlock()

	rel, ok := s.DeviceCodes[signature].(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	if s.InvalidatedDeviceCodes[signature] {
		return rel, oauth2.ErrInvalidatedDeviceCode
	}

	return rel, nil
}

// GetDeviceCodeSessionByUserCode returns the request stored against the user code signature, or oauth2.ErrNotFound when
// no session exists for it. When the device code of the request has been invalidated it returns the request alongside
// oauth2.ErrInvalidatedDeviceCode.
func (s *MemoryStore) GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error) {
	s.deviceCodesMutex.RLock()
	defer s.deviceCodesMutex.RUnlock()

	rel, ok := s.UserCodes[signature].(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	if s.InvalidatedDeviceCodes[rel.GetDeviceCodeSignature()] {
		return rel, oauth2.ErrInvalidatedDeviceCode
	}

	return rel, nil
}

// InvalidateDeviceCodeSession marks the device code signature as invalidated. It returns oauth2.ErrNotFound when no
// session exists for the signature, and oauth2.ErrInvalidatedDeviceCode when it is already invalidated.
func (s *MemoryStore) InvalidateDeviceCodeSession(_ context.Context, signature string) (err error) {
	s.deviceCodesMutex.Lock()
	defer s.deviceCodesMutex.Unlock()

	if _, ok := s.DeviceCodes[signature]; !ok {
		return oauth2.ErrNotFound
	}

	if s.InvalidatedDeviceCodes[signature] {
		return oauth2.ErrInvalidatedDeviceCode
	}

	if s.InvalidatedDeviceCodes == nil {
		s.InvalidatedDeviceCodes = make(map[string]bool)
	}

	s.InvalidatedDeviceCodes[signature] = true

	return nil
}

// CheckAndSetDPoPProofUsed implements rfc9449.DPoPReplayStorage. The jkt and nonce arguments are deliberately unused:
// this store keys on the endpoint the proof is bound to. See DPoPProofMarker for the trade-off that implies.
func (s *MemoryStore) CheckAndSetDPoPProofUsed(_ context.Context, jti, _, _, htm, htu string, exp time.Time) (bool, error) {
	s.dpopProofJTIsMutex.Lock()
	defer s.dpopProofJTIsMutex.Unlock()

	marker := DPoPProofMarker{JTI: jti, Method: htm, URL: htu}

	if existing, ok := s.DPoPProofJTIs[marker]; ok && existing.After(time.Now()) {
		return true, nil
	}

	pruneExpired(s.DPoPProofJTIs, &s.dpopProofJTIsPruneAt, time.Now())

	s.DPoPProofJTIs[marker] = exp

	return false, nil
}

// CreateDPoPNonce stores the DPoP nonce until exp.
func (s *MemoryStore) CreateDPoPNonce(_ context.Context, nonce string, exp time.Time) error {
	s.dpopNoncesMutex.Lock()
	defer s.dpopNoncesMutex.Unlock()

	pruneExpired(s.DPoPNonces, &s.dpopNoncesPruneAt, time.Now())

	s.DPoPNonces[nonce] = exp

	return nil
}

// IsDPoPNonceValid reports whether the DPoP nonce is known and has not expired.
func (s *MemoryStore) IsDPoPNonceValid(_ context.Context, nonce string) (bool, error) {
	s.dpopNoncesMutex.RLock()
	defer s.dpopNoncesMutex.RUnlock()

	exp, ok := s.DPoPNonces[nonce]
	if !ok {
		return false, nil
	}

	return exp.After(time.Now()), nil
}
