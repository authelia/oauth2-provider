// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2 (interfaces: AccessRequester)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/access_request.go authelia.com/provider/oauth2 AccessRequester
//

// Package mock is a generated GoMock package.
package mock

import (
	url "net/url"
	reflect "reflect"
	time "time"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockAccessRequester is a mock of AccessRequester interface.
type MockAccessRequester struct {
	ctrl     *gomock.Controller
	recorder *MockAccessRequesterMockRecorder
	isgomock struct{}
}

// MockAccessRequesterMockRecorder is the mock recorder for MockAccessRequester.
type MockAccessRequesterMockRecorder struct {
	mock *MockAccessRequester
}

// NewMockAccessRequester creates a new mock instance.
func NewMockAccessRequester(ctrl *gomock.Controller) *MockAccessRequester {
	mock := &MockAccessRequester{ctrl: ctrl}
	mock.recorder = &MockAccessRequesterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAccessRequester) EXPECT() *MockAccessRequesterMockRecorder {
	return m.recorder
}

// AppendRequestedScope mocks base method.
func (m *MockAccessRequester) AppendRequestedScope(scope string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AppendRequestedScope", scope)
}

// AppendRequestedScope indicates an expected call of AppendRequestedScope.
func (mr *MockAccessRequesterMockRecorder) AppendRequestedScope(scope any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppendRequestedScope", reflect.TypeOf((*MockAccessRequester)(nil).AppendRequestedScope), scope)
}

// GetClient mocks base method.
func (m *MockAccessRequester) GetClient() oauth2.Client {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClient")
	ret0, _ := ret[0].(oauth2.Client)
	return ret0
}

// GetClient indicates an expected call of GetClient.
func (mr *MockAccessRequesterMockRecorder) GetClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClient", reflect.TypeOf((*MockAccessRequester)(nil).GetClient))
}

// GetGrantTypes mocks base method.
func (m *MockAccessRequester) GetGrantTypes() oauth2.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantTypes")
	ret0, _ := ret[0].(oauth2.Arguments)
	return ret0
}

// GetGrantTypes indicates an expected call of GetGrantTypes.
func (mr *MockAccessRequesterMockRecorder) GetGrantTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantTypes", reflect.TypeOf((*MockAccessRequester)(nil).GetGrantTypes))
}

// GetGrantedAudience mocks base method.
func (m *MockAccessRequester) GetGrantedAudience() oauth2.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedAudience")
	ret0, _ := ret[0].(oauth2.Arguments)
	return ret0
}

// GetGrantedAudience indicates an expected call of GetGrantedAudience.
func (mr *MockAccessRequesterMockRecorder) GetGrantedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedAudience", reflect.TypeOf((*MockAccessRequester)(nil).GetGrantedAudience))
}

// GetGrantedScopes mocks base method.
func (m *MockAccessRequester) GetGrantedScopes() oauth2.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedScopes")
	ret0, _ := ret[0].(oauth2.Arguments)
	return ret0
}

// GetGrantedScopes indicates an expected call of GetGrantedScopes.
func (mr *MockAccessRequesterMockRecorder) GetGrantedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedScopes", reflect.TypeOf((*MockAccessRequester)(nil).GetGrantedScopes))
}

// GetID mocks base method.
func (m *MockAccessRequester) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID.
func (mr *MockAccessRequesterMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockAccessRequester)(nil).GetID))
}

// GetRequestForm mocks base method.
func (m *MockAccessRequester) GetRequestForm() url.Values {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestForm")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

// GetRequestForm indicates an expected call of GetRequestForm.
func (mr *MockAccessRequesterMockRecorder) GetRequestForm() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestForm", reflect.TypeOf((*MockAccessRequester)(nil).GetRequestForm))
}

// GetRequestedAt mocks base method.
func (m *MockAccessRequester) GetRequestedAt() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAt")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// GetRequestedAt indicates an expected call of GetRequestedAt.
func (mr *MockAccessRequesterMockRecorder) GetRequestedAt() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAt", reflect.TypeOf((*MockAccessRequester)(nil).GetRequestedAt))
}

// GetRequestedAudience mocks base method.
func (m *MockAccessRequester) GetRequestedAudience() oauth2.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAudience")
	ret0, _ := ret[0].(oauth2.Arguments)
	return ret0
}

// GetRequestedAudience indicates an expected call of GetRequestedAudience.
func (mr *MockAccessRequesterMockRecorder) GetRequestedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAudience", reflect.TypeOf((*MockAccessRequester)(nil).GetRequestedAudience))
}

// GetRequestedScopes mocks base method.
func (m *MockAccessRequester) GetRequestedScopes() oauth2.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedScopes")
	ret0, _ := ret[0].(oauth2.Arguments)
	return ret0
}

// GetRequestedScopes indicates an expected call of GetRequestedScopes.
func (mr *MockAccessRequesterMockRecorder) GetRequestedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedScopes", reflect.TypeOf((*MockAccessRequester)(nil).GetRequestedScopes))
}

// GetSession mocks base method.
func (m *MockAccessRequester) GetSession() oauth2.Session {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSession")
	ret0, _ := ret[0].(oauth2.Session)
	return ret0
}

// GetSession indicates an expected call of GetSession.
func (mr *MockAccessRequesterMockRecorder) GetSession() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSession", reflect.TypeOf((*MockAccessRequester)(nil).GetSession))
}

// GrantAudience mocks base method.
func (m *MockAccessRequester) GrantAudience(audience string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantAudience", audience)
}

// GrantAudience indicates an expected call of GrantAudience.
func (mr *MockAccessRequesterMockRecorder) GrantAudience(audience any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantAudience", reflect.TypeOf((*MockAccessRequester)(nil).GrantAudience), audience)
}

// GrantScope mocks base method.
func (m *MockAccessRequester) GrantScope(scope string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantScope", scope)
}

// GrantScope indicates an expected call of GrantScope.
func (mr *MockAccessRequesterMockRecorder) GrantScope(scope any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantScope", reflect.TypeOf((*MockAccessRequester)(nil).GrantScope), scope)
}

// Merge mocks base method.
func (m *MockAccessRequester) Merge(requester oauth2.Requester) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Merge", requester)
}

// Merge indicates an expected call of Merge.
func (mr *MockAccessRequesterMockRecorder) Merge(requester any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Merge", reflect.TypeOf((*MockAccessRequester)(nil).Merge), requester)
}

// Sanitize mocks base method.
func (m *MockAccessRequester) Sanitize(allowedParameters []string) oauth2.Requester {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sanitize", allowedParameters)
	ret0, _ := ret[0].(oauth2.Requester)
	return ret0
}

// Sanitize indicates an expected call of Sanitize.
func (mr *MockAccessRequesterMockRecorder) Sanitize(allowedParameters any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sanitize", reflect.TypeOf((*MockAccessRequester)(nil).Sanitize), allowedParameters)
}

// SetID mocks base method.
func (m *MockAccessRequester) SetID(id string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetID", id)
}

// SetID indicates an expected call of SetID.
func (mr *MockAccessRequesterMockRecorder) SetID(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetID", reflect.TypeOf((*MockAccessRequester)(nil).SetID), id)
}

// SetRequestedAudience mocks base method.
func (m *MockAccessRequester) SetRequestedAudience(audience oauth2.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedAudience", audience)
}

// SetRequestedAudience indicates an expected call of SetRequestedAudience.
func (mr *MockAccessRequesterMockRecorder) SetRequestedAudience(audience any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedAudience", reflect.TypeOf((*MockAccessRequester)(nil).SetRequestedAudience), audience)
}

// SetRequestedScopes mocks base method.
func (m *MockAccessRequester) SetRequestedScopes(scopes oauth2.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedScopes", scopes)
}

// SetRequestedScopes indicates an expected call of SetRequestedScopes.
func (mr *MockAccessRequesterMockRecorder) SetRequestedScopes(scopes any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedScopes", reflect.TypeOf((*MockAccessRequester)(nil).SetRequestedScopes), scopes)
}

// SetSession mocks base method.
func (m *MockAccessRequester) SetSession(session oauth2.Session) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetSession", session)
}

// SetSession indicates an expected call of SetSession.
func (mr *MockAccessRequesterMockRecorder) SetSession(session any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSession", reflect.TypeOf((*MockAccessRequester)(nil).SetSession), session)
}
