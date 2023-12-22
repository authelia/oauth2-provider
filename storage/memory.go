// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
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
	Key    *jose.JSONWebKey
	Scopes []string
}

type MemoryStore struct {
	Clients         map[string]oauth2.Client
	AuthorizeCodes  map[string]StoreAuthorizeCode
	IDSessions      map[string]oauth2.Requester
	AccessTokens    map[string]oauth2.Requester
	RefreshTokens   map[string]StoreRefreshToken
	PKCES           map[string]oauth2.Requester
	Users           map[string]MemoryUserRelation
	BlacklistedJTIs map[string]time.Time
	// In-memory request ID to token signatures
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string
	// Public keys to check signature in auth grant jwt assertion.
	IssuerPublicKeys map[string]IssuerPublicKeys
	PARSessions      map[string]oauth2.AuthorizeRequester

	clientsMutex                sync.RWMutex
	authorizeCodesMutex         sync.RWMutex
	idSessionsMutex             sync.RWMutex
	accessTokensMutex           sync.RWMutex
	refreshTokensMutex          sync.RWMutex
	pkcesMutex                  sync.RWMutex
	usersMutex                  sync.RWMutex
	blacklistedJTIsMutex        sync.RWMutex
	accessTokenRequestIDsMutex  sync.RWMutex
	refreshTokenRequestIDsMutex sync.RWMutex
	issuerPublicKeysMutex       sync.RWMutex
	parSessionsMutex            sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:                make(map[string]oauth2.Client),
		AuthorizeCodes:         make(map[string]StoreAuthorizeCode),
		IDSessions:             make(map[string]oauth2.Requester),
		AccessTokens:           make(map[string]oauth2.Requester),
		RefreshTokens:          make(map[string]StoreRefreshToken),
		PKCES:                  make(map[string]oauth2.Requester),
		Users:                  make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:  make(map[string]string),
		RefreshTokenRequestIDs: make(map[string]string),
		BlacklistedJTIs:        make(map[string]time.Time),
		IssuerPublicKeys:       make(map[string]IssuerPublicKeys),
		PARSessions:            make(map[string]oauth2.AuthorizeRequester),
	}
}

type StoreAuthorizeCode struct {
	active bool
	oauth2.Requester
}

type StoreRefreshToken struct {
	active bool
	oauth2.Requester
}

func NewExampleStore() *MemoryStore {
	return &MemoryStore{
		IDSessions: make(map[string]oauth2.Requester),
		Clients: map[string]oauth2.Client{
			"my-client": &oauth2.DefaultClient{
				ID:             "my-client",
				Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
				RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
			},
			"custom-lifespan-client": &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient: &oauth2.DefaultClient{
					ID:             "custom-lifespan-client",
					Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
					RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
					RedirectURIs:   []string{"http://localhost:3846/callback"},
					ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
					GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
					Scopes:         []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
				},
				TokenLifespans: &internal.TestLifespans,
			},
			"encoded:client": &oauth2.DefaultClient{
				ID:             "encoded:client",
				Secret:         []byte(`$2a$10$A7M8b65dSSKGHF0H2sNkn.9Z0hT8U1Nv6OWPV3teUUaczXkVkxuDS`), // = "encoded&password"
				RotatedSecrets: nil,
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
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
		AuthorizeCodes:         map[string]StoreAuthorizeCode{},
		AccessTokens:           map[string]oauth2.Requester{},
		RefreshTokens:          map[string]StoreRefreshToken{},
		PKCES:                  map[string]oauth2.Requester{},
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
		IssuerPublicKeys:       map[string]IssuerPublicKeys{},
		PARSessions:            map[string]oauth2.AuthorizeRequester{},
	}
}

func (s *MemoryStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester oauth2.Requester) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *MemoryStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester oauth2.Requester) (oauth2.Requester, error) {
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

func (s *MemoryStore) GetClient(_ context.Context, id string) (oauth2.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.Clients[id]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) SetTokenLifespans(clientID string, lifespans *oauth2.ClientLifespanConfig) error {
	if client, ok := s.Clients[clientID]; ok {
		if clc, ok := client.(*oauth2.DefaultClientWithCustomTokenLifespans); ok {
			clc.SetTokenLifespans(lifespans)
			return nil
		}
		return oauth2.ErrorToRFC6749Error(errors.New("failed to set token lifespans due to failed client type assertion"))
	}
	return oauth2.ErrNotFound
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.blacklistedJTIsMutex.RLock()
	defer s.blacklistedJTIsMutex.RUnlock()

	if exp, exists := s.BlacklistedJTIs[jti]; exists && exp.After(time.Now()) {
		return oauth2.ErrJTIKnown
	}

	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.blacklistedJTIsMutex.Lock()
	defer s.blacklistedJTIsMutex.Unlock()

	// delete expired jtis
	for j, e := range s.BlacklistedJTIs {
		if e.Before(time.Now()) {
			delete(s.BlacklistedJTIs, j)
		}
	}

	if _, exists := s.BlacklistedJTIs[jti]; exists {
		return oauth2.ErrJTIKnown
	}

	s.BlacklistedJTIs[jti] = exp
	return nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req oauth2.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

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

func (s *MemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return oauth2.ErrNotFound
	}
	rel.active = false
	s.AuthorizeCodes[code] = rel
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req oauth2.Requester) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	s.PKCES[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ oauth2.Session) (oauth2.Requester, error) {
	s.pkcesMutex.RLock()
	defer s.pkcesMutex.RUnlock()

	rel, ok := s.PKCES[code]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	delete(s.PKCES, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req oauth2.Requester) error {
	// We first lock accessTokenRequestIDsMutex and then accessTokensMutex because this is the same order
	// locking happens in RevokeAccessToken and using the same order prevents deadlocks.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ oauth2.Session) (oauth2.Requester, error) {
	s.accessTokensMutex.RLock()
	defer s.accessTokensMutex.RUnlock()

	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, oauth2.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	delete(s.AccessTokens, signature)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature string, req oauth2.Requester) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in RevokeRefreshToken and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	s.RefreshTokens[signature] = StoreRefreshToken{active: true, Requester: req}
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	return nil
}

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

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	delete(s.RefreshTokens, signature)
	return nil
}

func (s *MemoryStore) Authenticate(_ context.Context, name string, secret string) error {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	rel, ok := s.Users[name]
	if !ok {
		return oauth2.ErrNotFound
	}
	if rel.Password != secret {
		return oauth2.ErrNotFound.WithDebug("Invalid credentials")
	}
	return nil
}

func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()

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

func (s *MemoryStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	// no configuration option is available; grace period is not available with memory store
	return s.RevokeRefreshToken(ctx, requestID)
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.accessTokenRequestIDsMutex.RLock()
	defer s.accessTokenRequestIDsMutex.RUnlock()

	if signature, exists := s.AccessTokenRequestIDs[requestID]; exists {
		if err := s.DeleteAccessTokenSession(ctx, signature); err != nil {
			return err
		}
	}
	return nil
}

func (s *MemoryStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
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

func (s *MemoryStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
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

func (s *MemoryStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
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

func (s *MemoryStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := s.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (s *MemoryStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
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

// DeletePARSession deletes the context.
func (s *MemoryStore) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	delete(s.PARSessions, requestURI)
	return nil
}
