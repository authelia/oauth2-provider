// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	// DefaultClockSkew is how far in the future the 'iat' of a SET may be when Config.ClockSkew is zero. A negative
	// Config.ClockSkew permits none.
	DefaultClockSkew = 10 * time.Second

	// DefaultTokenRetention is how long the 'jti' of a received SET is remembered when Config.TokenRetention is not
	// positive, and the oldest 'iat' accepted when Config.MaxTokenAge is zero and Config.TokenRetention is not
	// positive.
	DefaultTokenRetention = 30 * 24 * time.Hour
)

// The descriptions of a SetError are fixed, and never hold a value of the SET.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
var (
	errSetNotCompact       = &SetError{Code: SetErrorInvalidRequest, Description: "The SET is not a compact serialized JWS or JWE."}
	errSetMalformed        = &SetError{Code: SetErrorInvalidRequest, Description: "The SET could not be parsed."}
	errSetNotDecrypted     = &SetError{Code: SetErrorInvalidRequest, Description: "The SET could not be decrypted, or does not nest a compact serialized JWS."}
	errSetNotNested        = &SetError{Code: SetErrorInvalidRequest, Description: "The encrypted SET does not nest a compact serialized JWS."}
	errSetHeader           = &SetError{Code: SetErrorInvalidRequest, Description: "The SET does not have the 'secevent+jwt' type header, or is encrypted without the headers of a nested JWT."}
	errSetClaims           = &SetError{Code: SetErrorInvalidRequest, Description: "The claims of the SET are not valid."}
	errSetTooOld           = &SetError{Code: SetErrorInvalidRequest, Description: "The SET was issued too long ago."}
	errSetEvent            = &SetError{Code: SetErrorInvalidRequest, Description: "The event of the SET is not valid."}
	errSetSigningAlgorithm = &SetError{Code: SetErrorInvalidKey, Description: "The signature algorithm of the SET is not allowed."}
	errSetKeyAlgorithm     = &SetError{Code: SetErrorInvalidKey, Description: "The key management algorithm of the SET is not allowed."}
	errSetSigningKey       = &SetError{Code: SetErrorInvalidKey, Description: "The Transmitter has no acceptable key for the signature of the SET."}
	errSetDecryptionKey    = &SetError{Code: SetErrorInvalidKey, Description: "The SET is not encrypted to a key of the Receiver."}
	errSetSignature        = &SetError{Code: SetErrorAuthenticationFailed, Description: "The signature of the SET is not valid."}
	errSetIssuer           = &SetError{Code: SetErrorInvalidIssuer, Description: "The issuer of the SET is not the Transmitter of the stream."}
	errSetAudience         = &SetError{Code: SetErrorInvalidAudience, Description: "The audience of the SET has no value of the audience of the stream."}
)

// reject returns a copy of the fixed error, so a caller can not change it.
func reject(fixed *SetError) (event *ReceivedEvent, serr *SetError, err error) {
	c := *fixed

	return nil, &c, nil
}

// validate returns the event of a SET received on the stream of the record, which the caller looked up from the
// request and never from the SET. A SET that is refused gives the SetError to report to the Transmitter. The err is a
// failure that is not a fault of the SET, such as the keys of the Transmitter being unreachable, which the Transmitter
// is not told is a SET error so that it delivers the SET again.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
// See: https://www.rfc-editor.org/rfc/rfc8417#section-5.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1
//
//nolint:gocyclo
func (r *Receiver) validate(ctx context.Context, record *StreamRecord, token string) (event *ReceivedEvent, serr *SetError, err error) {
	switch {
	case record == nil || record.Issuer == "":
		return nil, nil, errors.New("ssfreceiver: the stream record has no issuer")
	case r.Config.Strategy == nil:
		return nil, nil, errors.New("ssfreceiver: the strategy is not configured")
	}

	var (
		jwe       *jose.JSONWebEncryption
		signed    = token
		encrypted = jwt.IsEncryptedJWT(token)
		keyAlgs   = asymmetricKeyAlgorithms()
	)

	if encrypted {
		// RFC 8417 Section 5.1: no secret is shared with a Transmitter, so only an asymmetric key management
		// algorithm is accepted.
		if alg, ok := compactAlgorithm(token); !ok {
			return reject(errSetMalformed)
		} else if !slices.Contains(keyAlgs, jose.KeyAlgorithm(alg)) {
			return reject(errSetKeyAlgorithm)
		}

		if signed, _, jwe, err = r.Config.Strategy.Decrypt(ctx, token, jwt.WithKeyAlgorithm(keyAlgs...)); err != nil {
			if serr, err = decryptFault(err); err != nil {
				return nil, nil, err
			}

			return reject(serr)
		}

		if !jwt.IsSignedJWT(signed) {
			return reject(errSetNotNested)
		}
	} else if !jwt.IsSignedJWT(token) {
		return reject(errSetNotCompact)
	}

	algs := r.signingAlgs()

	// The algorithm is read here only to tell an algorithm that is not allowed from a SET that is malformed. The
	// strategy is given the same algorithms, and enforces them.
	if alg, ok := compactAlgorithm(signed); !ok {
		return reject(errSetMalformed)
	} else if !slices.Contains(algs, jose.SignatureAlgorithm(alg)) {
		return reject(errSetSigningAlgorithm)
	}

	var decoded *jwt.Token

	if decoded, err = r.Config.Strategy.Decode(ctx, signed, jwt.WithKeyFunc(r.keyFunc(record)), jwt.WithSigAlgorithm(algs...), jwt.WithKeyAlgorithm(keyAlgs...)); err != nil {
		if serr, err = decodeFault(err); err != nil {
			return nil, nil, err
		}

		return reject(serr)
	}

	// The strategy returns no error for a token it did not verify, such as one with an 'alg' of 'none'.
	if decoded == nil || !decoded.IsSignatureValid() {
		return reject(errSetSignature)
	}

	decoded.AssignJWE(jwe)

	// SSF Section 4.1.1, RFC 8417 Section 2.3: the SET is explicitly typed.
	if err = decoded.Valid(jwt.ValidateTypes(jwt.JSONWebTokenTypeSecurityEventToken)); err != nil {
		return reject(errSetHeader)
	}

	var (
		payload []byte
		claims  *jwt.SecurityEventTokenClaims
	)

	// The claims are parsed from the payload of the verified JWS, which keeps the numbers and the subject members the
	// claims of the decoded token lose.
	if payload, err = base64.RawURLEncoding.DecodeString(strings.Split(signed, ".")[1]); err != nil {
		return reject(errSetMalformed)
	}

	if claims, err = jwt.ParseSecurityEventTokenClaims(payload); err != nil {
		return reject(errSetClaims)
	}

	now := r.time()

	var faults uint32

	// SSF Section 4.1.6: the 'iss' is the issuer of the stream and of the metadata, both the Issuer of the record. SSF
	// Section 4.1.8, RFC 8935 Section 2: the 'aud' has a value of the stream audience.
	if err = claims.Valid(
		jwt.ValidateIssuer(record.Issuer),
		jwt.ValidateAudienceAny(record.Audience...),
		jwt.ValidateClockSkew(r.clockSkew()),
		jwt.ValidateTimeFunc(func() time.Time { return now }),
		jwt.ValidateSecurityEventReceiver(),
	); err != nil {
		var fault *jwt.ValidationError

		if !errors.As(err, &fault) {
			return reject(errSetClaims)
		}

		faults = fault.Errors
	}

	// A record without an audience has no value an 'aud' could match.
	if len(record.Audience) == 0 {
		faults |= jwt.ValidationErrorAudience
	}

	// The issuer is reported first, then the audience, then the rest.
	switch {
	case faults&jwt.ValidationErrorIssuer != 0:
		return reject(errSetIssuer)
	case faults&jwt.ValidationErrorAudience != 0:
		return reject(errSetAudience)
	case faults != 0:
		return reject(errSetClaims)
	}

	// A SET older than the time its 'jti' is remembered for could be replayed, so it is refused. The clock skew does
	// not extend the age.
	if age, ok := r.maxTokenAge(); ok && now.Sub(claims.GetIssuedAtSafe()) > age {
		return reject(errSetTooOld)
	}

	event = &ReceivedEvent{
		Stream:    record.Clone(),
		Claims:    claims,
		Token:     signed,
		Encrypted: encrypted,
	}

	// The secrets of the stream are not handed to the application.
	event.Stream.Delivery.AuthorizationHeader, event.Stream.PendingAuthorizationHeader = "", ""

	// The claims have exactly one event, and its payload is an object.
	for uri, value := range claims.Events {
		event.Type = uri
		event.Payload, _ = value.(map[string]any)

		if event.Event, err = jwt.DecodeSecurityEvent(uri, event.Payload); err != nil {
			return reject(errSetEvent)
		}
	}

	return event, nil, nil
}

// deduplicate calls dispatch for an event whose SET was not received before on its stream, and then remembers the
// SET. A SET that is known is acknowledged again and not dispatched. An error of dispatch is returned as it is and the
// SET is not remembered, so the Transmitter can deliver it again. A crash between dispatch and the mark, or a
// concurrent delivery of the same SET, can repeat the dispatch, so dispatch must be idempotent on the issuer and the
// 'jti'.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
func (r *Receiver) deduplicate(ctx context.Context, event *ReceivedEvent, dispatch func(ctx context.Context) error) (known bool, err error) {
	if known, err = r.isTokenKnown(ctx, event); err != nil || known {
		return known, err
	}

	if err = dispatch(ctx); err != nil {
		return false, err
	}

	return false, r.markTokenReceived(ctx, event)
}

// accept dispatches a validated event once, and maps the outcome for the Transmitter, the same for push and for poll.
// Without a SetError or an error the SET is acknowledged, and handed is the copy of the event the EventHandler
// accepted, which is nil for a SET received before and for an event it was not handed. A SetError is reported to the
// Transmitter. An error is a failure that is not a fault of the SET, which includes a *SetError without an 'err'
// value: the SET is not acknowledged and is not reported, so the Transmitter delivers it again. With an error handed
// is the event the EventHandler accepted before the SET could not be remembered, and nil otherwise.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
func (r *Receiver) accept(ctx context.Context, event *ReceivedEvent) (handed *ReceivedEvent, serr *SetError, err error) {
	var perr error

	if _, err = r.deduplicate(ctx, event, func(ctx context.Context) error {
		if handed, perr = r.process(ctx, event); perr != nil {
			handed = nil
		}

		return perr
	}); err == nil {
		return handed, nil, nil
	}

	// Only the EventHandler reports a fault of the SET: an error of the store is never one, whatever it wraps.
	if perr == nil {
		return handed, nil, err
	}

	if err = handlerFault(perr); errors.As(err, &serr) {
		return nil, serr, nil
	}

	return nil, nil, err
}

// isTokenKnown returns true when the SET of the event was received before on its stream.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
func (r *Receiver) isTokenKnown(ctx context.Context, event *ReceivedEvent) (known bool, err error) {
	if err = r.checkTokenStorage(event); err != nil {
		return false, err
	}

	if known, err = r.Store.IsSSFReceiverTokenKnown(ctx, event.Stream.Issuer, event.Stream.StreamID, event.Claims.JTI); err != nil {
		return false, fmt.Errorf("ssfreceiver: the security event token could not be looked up: %w", err)
	}

	return known, nil
}

// markTokenReceived remembers the SET of the event until the later of Config.TokenRetention from now and the time its
// 'iat' is older than Config.MaxTokenAge, so a SET is refused by age before it is forgotten. A SET another delivery
// marked in the meantime is not an error.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
func (r *Receiver) markTokenReceived(ctx context.Context, event *ReceivedEvent) (err error) {
	if err = r.checkTokenStorage(event); err != nil {
		return err
	}

	expires := r.time().Add(r.tokenRetention())

	if age, ok := r.maxTokenAge(); ok {
		if refused := event.Claims.GetIssuedAtSafe().Add(age); refused.After(expires) {
			expires = refused
		}
	}

	if err = r.Store.MarkSSFReceiverTokenReceived(ctx, event.Stream.Issuer, event.Stream.StreamID, event.Claims.JTI, expires); err != nil && !errors.Is(err, oauth2.ErrJTIKnown) {
		return fmt.Errorf("ssfreceiver: the security event token could not be marked as received: %w", err)
	}

	return nil
}

func (r *Receiver) checkTokenStorage(event *ReceivedEvent) (err error) {
	switch {
	case r.Store == nil:
		return errors.New("ssfreceiver: the storage is not configured")
	case event == nil || event.Stream == nil || event.Claims == nil || event.Claims.JTI == "":
		return errors.New("ssfreceiver: the event has no stream or no 'jti'")
	default:
		return nil
	}
}

// compactAlgorithm returns the 'alg' of the header of a compact serialized JWS or JWE.
func compactAlgorithm(token string) (alg string, ok bool) {
	segment, _, _ := strings.Cut(token, ".")

	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return "", false
	}

	header := struct {
		Algorithm string `json:"alg"`
	}{}

	if err = json.Unmarshal(data, &header); err != nil {
		return "", false
	}

	return header.Algorithm, true
}

// decryptFault returns the SetError for an encrypted SET the strategy did not decrypt, or the error when the key of
// the Receiver could not be looked up for a reason that is not a fault of the SET.
func decryptFault(cause error) (serr *SetError, err error) {
	var fault *jwt.ValidationError

	if !errors.As(cause, &fault) {
		return nil, fmt.Errorf("ssfreceiver: the security event token could not be decrypted: %w", cause)
	}

	if !fault.Has(jwt.ValidationErrorUnverifiable) {
		return errSetNotDecrypted, nil
	}

	var lookup *jwt.JWKLookupError

	// The Receiver has no key for the 'kid' and 'alg'.
	if errors.As(fault.Inner, &lookup) {
		return errSetDecryptionKey, nil
	}

	// The strategy has no issuer, or its key provider failed.
	if fault.Inner != nil {
		return nil, fmt.Errorf("ssfreceiver: the decryption key of the receiver could not be resolved: %w", fault.Inner)
	}

	return nil, fmt.Errorf("ssfreceiver: the decryption key of the receiver could not be resolved: %w", cause)
}

// decodeFault returns the SetError for a signed SET the strategy did not decode, or the error when the key could not
// be resolved for a reason that is not a fault of the SET.
func decodeFault(cause error) (serr *SetError, err error) {
	var fault *jwt.ValidationError

	if !errors.As(cause, &fault) {
		return nil, fmt.Errorf("ssfreceiver: the security event token could not be decoded: %w", cause)
	}

	switch {
	case fault.Has(jwt.ValidationErrorUnverifiable):
		if errors.Is(fault.Inner, ErrSigningKey) {
			return errSetSigningKey, nil
		}

		// The metadata or the keys of the Transmitter could not be retrieved.
		if fault.Inner != nil {
			return nil, fmt.Errorf("ssfreceiver: the signing key of the transmitter could not be resolved: %w", fault.Inner)
		}

		return nil, fmt.Errorf("ssfreceiver: the signing key of the transmitter could not be resolved: %w", cause)
	case fault.Has(jwt.ValidationErrorSignatureInvalid):
		return errSetSignature, nil
	default:
		return errSetMalformed, nil
	}
}

// asymmetricKeyAlgorithms returns the JWE key management algorithms that use a key pair of the Receiver.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-5.1
func asymmetricKeyAlgorithms() (algs []jose.KeyAlgorithm) {
	for _, alg := range jwt.EncryptionKeyAlgorithms {
		if !jwt.IsEncryptedJWTClientSecretAlg(alg) {
			algs = append(algs, alg)
		}
	}

	return algs
}

// signingAlgs returns the allowed SET signature algorithms, which are never 'none' or symmetric, and are RS256 alone
// under the CAEP Interoperability Profile whatever Config.SigningAlgs is.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-5.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
func (r *Receiver) signingAlgs() (algs []jose.SignatureAlgorithm) {
	// Profile Section 2.6: every event is signed using RS256.
	if r.Config.EnforceCAEPInteroperabilityProfile {
		return []jose.SignatureAlgorithm{jose.RS256}
	}

	if len(r.Config.SigningAlgs) == 0 {
		return []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	}

	return jwt.ToAsymmetricSignatureAlgorithms(r.Config.SigningAlgs)
}

func (r *Receiver) clockSkew() (skew time.Duration) {
	switch {
	case r.Config.ClockSkew == 0:
		return DefaultClockSkew
	case r.Config.ClockSkew < 0:
		return 0
	default:
		return r.Config.ClockSkew
	}
}

func (r *Receiver) tokenRetention() (retention time.Duration) {
	if r.Config.TokenRetention > 0 {
		return r.Config.TokenRetention
	}

	return DefaultTokenRetention
}

// maxTokenAge returns the oldest 'iat' accepted, which is the retention when Config.MaxTokenAge is zero, and false when
// a negative Config.MaxTokenAge disables the check.
func (r *Receiver) maxTokenAge() (age time.Duration, ok bool) {
	switch {
	case r.Config.MaxTokenAge < 0:
		return 0, false
	case r.Config.MaxTokenAge == 0:
		return r.tokenRetention(), true
	default:
		return r.Config.MaxTokenAge, true
	}
}

// time returns the current time of the Receiver.
func (r *Receiver) time() time.Time {
	return r.metadata.time()
}
