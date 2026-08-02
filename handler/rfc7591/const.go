package rfc7591

import "time"

// ClientIDEntropy is the number of alphanumeric runes generated for a new 'client_id'.
const ClientIDEntropy = 64

// Kind identifies which role a client registration session plays. It is the whole discriminator between the two
// tokens RFC 7591 and RFC 7592 involve, and between either of them and an ordinary access token.
type Kind int

// The values below are a storage contract, not merely an internal enumeration: a Kind is persisted as the bare
// integer it evaluates to (see DefaultSession's 'client_registration_kind' JSON tag), so stored sessions minted by an
// earlier build are read back through whatever this block says the number means now. Inserting a new value into the
// middle of the iota therefore silently reinterprets every session already in storage - a KindManage session would
// come back as KindCreate, turning a token scoped to one client into one permitted to register new ones. Only ever
// append.
const (
	// KindNone is the zero value and means the session is not a client registration session at all. An ordinary
	// access token hydrated into a DefaultSession lands here, which is what makes a foreign token fail closed.
	KindNone Kind = iota

	// KindCreate permits the holder to register new clients at the client registration endpoint.
	KindCreate

	// KindManage permits the holder to manage exactly one already registered client, at that client's
	// registration_client_uri.
	KindManage
)

// NonExpiringTokenLifespan is the lifespan applied to a client registration access token whose configured lifespan is
// zero, i.e. one documented as never expiring - the normal expectation for an RFC 7592 'registration_access_token',
// which has no re-issue path.
//
// A zero lifespan cannot simply leave the session's 'expires_at' unset. hoauth2.HMACCoreStrategy.ValidateAccessToken
// treats an unset access token expiry not as "no expiry" but as "expires at RequestedAt plus the global
// AccessTokenLifespan", so an unset expiry would silently retire the token after one hour by default; under
// EnforceJWTProfileAccessTokens no 'exp' claim would be emitted at all and the very same configuration would produce a
// token that genuinely never expires. Recording an explicit far-future expiry instead makes both strategies agree and
// makes "never expires" mean what it says.
//
// A century is chosen because it is unambiguously beyond any deployment's horizon while remaining far away from
// time.Time's and time.Duration's limits, so it serialises safely into a JWT 'exp' claim as seconds since the epoch.
const NonExpiringTokenLifespan = 100 * 365 * 24 * time.Hour

// SectorIdentifierMaxBodyBytes bounds the number of bytes read from a 'sector_identifier_uri' response body. The
// URI is client-supplied, so the fetch must not be allowed to consume unbounded memory.
const SectorIdentifierMaxBodyBytes = 1 << 20
