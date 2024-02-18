package rfc8693

import (
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
)

// Session is required to support token exchange
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)

	SetActorToken(token map[string]any)

	GetActorToken() map[string]any

	SetSubjectToken(token map[string]any)

	GetSubjectToken() map[string]any

	SetAct(act map[string]any)

	AccessTokenClaimsMap() map[string]any
}

type DefaultSession struct {
	*openid.DefaultSession

	ActorToken   map[string]any `json:"-"`
	SubjectToken map[string]any `json:"-"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (s *DefaultSession) SetActorToken(token map[string]any) {
	s.ActorToken = token
}

func (s *DefaultSession) GetActorToken() map[string]any {
	return s.ActorToken
}

func (s *DefaultSession) SetSubjectToken(token map[string]any) {
	s.SubjectToken = token
}

func (s *DefaultSession) GetSubjectToken() map[string]any {
	return s.SubjectToken
}

func (s *DefaultSession) SetAct(act map[string]any) {
	s.Extra[consts.ClaimActor] = act
}

func (s *DefaultSession) AccessTokenClaimsMap() map[string]any {
	tokenObject := map[string]any{
		consts.ClaimSubject:  s.GetSubject(),
		consts.ClaimUsername: s.GetUsername(),
	}

	for k, v := range s.Extra {
		tokenObject[k] = v
	}

	return tokenObject
}
