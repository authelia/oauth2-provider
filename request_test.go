// Copyright © 2026 Authelia
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestNewRequest(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T, actual *Request)
	}{
		{
			name: "ShouldInitializeAllFields",
			check: func(t *testing.T, actual *Request) {
				assert.NotNil(t, actual.Client)
				assert.NotNil(t, actual.RequestedScope)
				assert.NotNil(t, actual.RequestedAudience)
				assert.NotNil(t, actual.GrantedScope)
				assert.NotNil(t, actual.GrantedAudience)
				assert.NotNil(t, actual.Form)
				assert.False(t, actual.RequestedAt.IsZero())
			},
		},
		{
			name: "ShouldReturnEmptyArguments",
			check: func(t *testing.T, actual *Request) {
				assert.Empty(t, actual.RequestedScope)
				assert.Empty(t, actual.RequestedAudience)
				assert.Empty(t, actual.GrantedScope)
				assert.Empty(t, actual.GrantedAudience)
				assert.Empty(t, actual.Form)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewRequest()
			tc.check(t, actual)
		})
	}
}

func TestRequestGetters(t *testing.T) {
	requestedAt := time.Now().UTC()
	session := &DefaultSession{Subject: "alice"}
	client := &DefaultClient{ID: "client-id"}

	r := &Request{
		RequestedAt:       requestedAt,
		Client:            client,
		RequestedScope:    Arguments{"req-scope"},
		GrantedScope:      Arguments{"granted-scope"},
		RequestedAudience: Arguments{"req-aud"},
		GrantedAudience:   Arguments{"granted-aud"},
		Form:              url.Values{"foo": []string{"bar"}},
		Session:           session,
		Lang:              language.German,
	}

	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnRequestedAt",
			check: func(t *testing.T) {
				assert.Equal(t, requestedAt, r.GetRequestedAt())
			},
		},
		{
			name: "ShouldReturnClient",
			check: func(t *testing.T) {
				assert.Equal(t, client, r.GetClient())
			},
		},
		{
			name: "ShouldReturnGrantedScopes",
			check: func(t *testing.T) {
				assert.Equal(t, Arguments{"granted-scope"}, r.GetGrantedScopes())
			},
		},
		{
			name: "ShouldReturnRequestedScopes",
			check: func(t *testing.T) {
				assert.Equal(t, Arguments{"req-scope"}, r.GetRequestedScopes())
			},
		},
		{
			name: "ShouldReturnGrantedAudience",
			check: func(t *testing.T) {
				assert.Equal(t, Arguments{"granted-aud"}, r.GetGrantedAudience())
			},
		},
		{
			name: "ShouldReturnRequestedAudience",
			check: func(t *testing.T) {
				assert.Equal(t, Arguments{"req-aud"}, r.GetRequestedAudience())
			},
		},
		{
			name: "ShouldReturnForm",
			check: func(t *testing.T) {
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, r.GetRequestForm())
			},
		},
		{
			name: "ShouldReturnSession",
			check: func(t *testing.T) {
				assert.Equal(t, session, r.GetSession())
			},
		},
		{
			name: "ShouldReturnLang",
			check: func(t *testing.T) {
				assert.Equal(t, language.German, r.GetLang())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestRequestSetters(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldSetID",
			check: func(t *testing.T) {
				r := &Request{}
				r.SetID("abc")
				assert.Equal(t, "abc", r.GetID())
			},
		},
		{
			name: "ShouldGenerateIDWhenUnset",
			check: func(t *testing.T) {
				r := &Request{}
				actual := r.GetID()
				assert.NotEmpty(t, actual)
				assert.Equal(t, actual, r.GetID())
			},
		},
		{
			name: "ShouldSetRequestedAt",
			check: func(t *testing.T) {
				r := &Request{}
				now := time.Now().UTC()
				r.SetRequestedAt(now)
				assert.Equal(t, now, r.GetRequestedAt())
			},
		},
		{
			name: "ShouldSetSession",
			check: func(t *testing.T) {
				r := &Request{}
				session := &DefaultSession{Subject: "bob"}
				r.SetSession(session)
				assert.Equal(t, session, r.GetSession())
			},
		},
		{
			name: "ShouldSetRequestedScopes",
			check: func(t *testing.T) {
				r := &Request{RequestedScope: Arguments{"existing"}}
				r.SetRequestedScopes(Arguments{"one", "two"})
				assert.Equal(t, Arguments{"one", "two"}, r.GetRequestedScopes())
			},
		},
		{
			name: "ShouldSetRequestedScopesDeduplicating",
			check: func(t *testing.T) {
				r := &Request{}
				r.SetRequestedScopes(Arguments{"one", "two", "one"})
				assert.Equal(t, Arguments{"one", "two"}, r.GetRequestedScopes())
			},
		},
		{
			name: "ShouldSetRequestedAudience",
			check: func(t *testing.T) {
				r := &Request{RequestedAudience: Arguments{"existing"}}
				r.SetRequestedAudience(Arguments{"aud-1", "aud-2"})
				assert.Equal(t, Arguments{"aud-1", "aud-2"}, r.GetRequestedAudience())
			},
		},
		{
			name: "ShouldSetRequestedAudienceDeduplicating",
			check: func(t *testing.T) {
				r := &Request{}
				r.SetRequestedAudience(Arguments{"aud-1", "aud-2", "aud-1"})
				assert.Equal(t, Arguments{"aud-1", "aud-2"}, r.GetRequestedAudience())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestRequestAppendRequestedScope(t *testing.T) {
	testCases := []struct {
		name     string
		initial  Arguments
		appends  []string
		expected Arguments
	}{
		{
			name:     "ShouldAppendToEmptyScopes",
			initial:  nil,
			appends:  []string{"read"},
			expected: Arguments{"read"},
		},
		{
			name:     "ShouldAppendMultipleScopes",
			initial:  Arguments{"read"},
			appends:  []string{"write", "delete"},
			expected: Arguments{"read", "write", "delete"},
		},
		{
			name:     "ShouldNotAppendDuplicateScope",
			initial:  Arguments{"read"},
			appends:  []string{"read"},
			expected: Arguments{"read"},
		},
		{
			name:     "ShouldNotAppendDuplicateWithExisting",
			initial:  Arguments{"read", "write"},
			appends:  []string{"write"},
			expected: Arguments{"read", "write"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{RequestedScope: tc.initial}
			for _, s := range tc.appends {
				r.AppendRequestedScope(s)
			}
			assert.Equal(t, tc.expected, r.GetRequestedScopes())
		})
	}
}

func TestRequestAppendRequestedAudience(t *testing.T) {
	testCases := []struct {
		name     string
		initial  Arguments
		appends  []string
		expected Arguments
	}{
		{
			name:     "ShouldAppendToEmptyAudience",
			initial:  nil,
			appends:  []string{"aud-1"},
			expected: Arguments{"aud-1"},
		},
		{
			name:     "ShouldAppendMultipleAudiences",
			initial:  Arguments{"aud-1"},
			appends:  []string{"aud-2", "aud-3"},
			expected: Arguments{"aud-1", "aud-2", "aud-3"},
		},
		{
			name:     "ShouldNotAppendDuplicateAudience",
			initial:  Arguments{"aud-1"},
			appends:  []string{"aud-1"},
			expected: Arguments{"aud-1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{RequestedAudience: tc.initial}
			for _, a := range tc.appends {
				r.AppendRequestedAudience(a)
			}
			assert.Equal(t, tc.expected, r.GetRequestedAudience())
		})
	}
}

func TestRequestGrantScope(t *testing.T) {
	testCases := []struct {
		name     string
		initial  Arguments
		grants   []string
		expected Arguments
	}{
		{
			name:     "ShouldGrantToEmptyScopes",
			initial:  nil,
			grants:   []string{"read"},
			expected: Arguments{"read"},
		},
		{
			name:     "ShouldGrantMultipleScopes",
			initial:  Arguments{"read"},
			grants:   []string{"write", "delete"},
			expected: Arguments{"read", "write", "delete"},
		},
		{
			name:     "ShouldNotGrantDuplicateScope",
			initial:  Arguments{"read"},
			grants:   []string{"read"},
			expected: Arguments{"read"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{GrantedScope: tc.initial}
			for _, s := range tc.grants {
				r.GrantScope(s)
			}
			assert.Equal(t, tc.expected, r.GetGrantedScopes())
		})
	}
}

func TestRequestGrantAudience(t *testing.T) {
	testCases := []struct {
		name     string
		initial  Arguments
		grants   []string
		expected Arguments
	}{
		{
			name:     "ShouldGrantToEmptyAudience",
			initial:  nil,
			grants:   []string{"aud-1"},
			expected: Arguments{"aud-1"},
		},
		{
			name:     "ShouldGrantMultipleAudiences",
			initial:  Arguments{"aud-1"},
			grants:   []string{"aud-2", "aud-3"},
			expected: Arguments{"aud-1", "aud-2", "aud-3"},
		},
		{
			name:     "ShouldNotGrantDuplicateAudience",
			initial:  Arguments{"aud-1"},
			grants:   []string{"aud-1"},
			expected: Arguments{"aud-1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{GrantedAudience: tc.initial}
			for _, a := range tc.grants {
				r.GrantAudience(a)
			}
			assert.Equal(t, tc.expected, r.GetGrantedAudience())
		})
	}
}

func TestRequestMerge(t *testing.T) {
	testCases := []struct {
		name  string
		setup func() (target *Request, source *Request)
		check func(t *testing.T, target *Request, source *Request)
	}{
		{
			name: "ShouldMergeAllFieldsFromSource",
			setup: func() (*Request, *Request) {
				source := &Request{
					ID:                "123",
					RequestedAt:       time.Now().UTC(),
					Client:            &DefaultClient{ID: "123"},
					RequestedScope:    Arguments{"scope-3", "scope-4"},
					RequestedAudience: Arguments{"aud-3", "aud-4"},
					GrantedScope:      Arguments{"scope-1", "scope-2"},
					GrantedAudience:   Arguments{"aud-1", "aud-2"},
					Form:              url.Values{"foo": []string{"fasdf"}},
					Session:           new(DefaultSession),
				}
				target := &Request{
					RequestedAt:    time.Now().UTC(),
					Client:         &DefaultClient{},
					RequestedScope: Arguments{},
					GrantedScope:   Arguments{},
					Form:           url.Values{},
					Session:        new(DefaultSession),
				}
				return target, source
			},
			check: func(t *testing.T, target *Request, source *Request) {
				assert.EqualValues(t, source.RequestedAt, target.RequestedAt)
				assert.EqualValues(t, source.Client, target.Client)
				assert.EqualValues(t, source.RequestedScope, target.RequestedScope)
				assert.EqualValues(t, source.RequestedAudience, target.RequestedAudience)
				assert.EqualValues(t, source.GrantedScope, target.GrantedScope)
				assert.EqualValues(t, source.GrantedAudience, target.GrantedAudience)
				assert.EqualValues(t, source.Form, target.Form)
				assert.EqualValues(t, source.Session, target.Session)
				assert.EqualValues(t, source.ID, target.ID)
			},
		},
		{
			name: "ShouldNotDuplicateExistingScopes",
			setup: func() (*Request, *Request) {
				source := &Request{
					ID:             "123",
					Client:         &DefaultClient{},
					RequestedScope: Arguments{"scope-1", "scope-2"},
					GrantedScope:   Arguments{"granted-1"},
					Form:           url.Values{},
					Session:        new(DefaultSession),
				}
				target := &Request{
					RequestedScope: Arguments{"scope-1"},
					GrantedScope:   Arguments{"granted-1"},
					Form:           url.Values{},
				}
				return target, source
			},
			check: func(t *testing.T, target *Request, source *Request) {
				assert.ElementsMatch(t, Arguments{"scope-1", "scope-2"}, target.RequestedScope)
				assert.ElementsMatch(t, Arguments{"granted-1"}, target.GrantedScope)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			target, source := tc.setup()
			target.Merge(source)
			tc.check(t, target, source)
		})
	}
}

func TestRequestSanitize(t *testing.T) {
	build := func() *Request {
		return &Request{
			RequestedAt:    time.Now().UTC(),
			Client:         &DefaultClient{ID: "123"},
			RequestedScope: Arguments{"asdff"},
			GrantedScope:   Arguments{"asdf"},
			Form: url.Values{
				"foo": []string{"fasdf"},
				"bar": []string{"fasdf", "faaaa"},
				"baz": []string{"fasdf"},

				consts.FormParameterGrantType:    []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterResponseType: []string{consts.ResponseTypeImplicitFlowIDToken},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterScope:        []string{"read"},
			},
			Session: new(DefaultSession),
		}
	}

	testCases := []struct {
		name  string
		check func(t *testing.T, a *Request)
	}{
		{
			name: "ShouldPreserveAllowedParameters",
			check: func(t *testing.T, a *Request) {
				b := a.Sanitize([]string{"bar", "baz"})

				assert.NotEqual(t, a.Form.Encode(), b.GetRequestForm().Encode())

				assert.Empty(t, b.GetRequestForm().Get("foo"))
				assert.Equal(t, "fasdf", b.GetRequestForm().Get("bar"))
				assert.Equal(t, []string{"fasdf", "faaaa"}, b.GetRequestForm()["bar"])
				assert.Equal(t, "fasdf", b.GetRequestForm().Get("baz"))
			},
		},
		{
			name: "ShouldNotMutateOriginal",
			check: func(t *testing.T, a *Request) {
				_ = a.Sanitize([]string{"bar", "baz"})

				assert.Equal(t, "fasdf", a.GetRequestForm().Get("foo"))
				assert.Equal(t, "fasdf", a.GetRequestForm().Get("bar"))
				assert.Equal(t, []string{"fasdf", "faaaa"}, a.GetRequestForm()["bar"])
				assert.Equal(t, "fasdf", a.GetRequestForm().Get("baz"))
				assert.Equal(t, consts.GrantTypeAuthorizationCode, a.GetRequestForm().Get(consts.FormParameterGrantType))
				assert.Equal(t, consts.ResponseTypeImplicitFlowIDToken, a.GetRequestForm().Get(consts.FormParameterResponseType))
				assert.Equal(t, "1234", a.GetRequestForm().Get(consts.FormParameterClientID))
				assert.Equal(t, "read", a.GetRequestForm().Get(consts.FormParameterScope))
			},
		},
		{
			name: "ShouldAlwaysPreserveStandardParameters",
			check: func(t *testing.T, a *Request) {
				b := a.Sanitize(nil)

				assert.Equal(t, consts.GrantTypeAuthorizationCode, b.GetRequestForm().Get(consts.FormParameterGrantType))
				assert.Equal(t, consts.ResponseTypeImplicitFlowIDToken, b.GetRequestForm().Get(consts.FormParameterResponseType))
				assert.Equal(t, "1234", b.GetRequestForm().Get(consts.FormParameterClientID))
				assert.Equal(t, "read", b.GetRequestForm().Get(consts.FormParameterScope))
				assert.Empty(t, b.GetRequestForm().Get("foo"))
				assert.Empty(t, b.GetRequestForm().Get("bar"))
				assert.Empty(t, b.GetRequestForm().Get("baz"))
			},
		},
		{
			name: "ShouldPreserveIDInSanitizedCopy",
			check: func(t *testing.T, a *Request) {
				a.ID = "request-id"
				b := a.Sanitize(nil)

				assert.Equal(t, "request-id", b.GetID())
			},
		},
		{
			name: "ShouldGenerateIDIfMissing",
			check: func(t *testing.T, a *Request) {
				b := a.Sanitize(nil)
				b.GetID()
				assert.NotEmpty(t, b.GetID())
				assert.Equal(t, a.ID, b.GetID())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, build())
		})
	}
}
