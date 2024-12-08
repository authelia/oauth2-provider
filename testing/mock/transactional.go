// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/storage (interfaces: Transactional)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/transactional.go authelia.com/provider/oauth2/storage Transactional
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockTransactional is a mock of Transactional interface.
type MockTransactional struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionalMockRecorder
	isgomock struct{}
}

// MockTransactionalMockRecorder is the mock recorder for MockTransactional.
type MockTransactionalMockRecorder struct {
	mock *MockTransactional
}

// NewMockTransactional creates a new mock instance.
func NewMockTransactional(ctrl *gomock.Controller) *MockTransactional {
	mock := &MockTransactional{ctrl: ctrl}
	mock.recorder = &MockTransactionalMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransactional) EXPECT() *MockTransactionalMockRecorder {
	return m.recorder
}

// BeginTX mocks base method.
func (m *MockTransactional) BeginTX(ctx context.Context) (context.Context, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeginTX", ctx)
	ret0, _ := ret[0].(context.Context)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeginTX indicates an expected call of BeginTX.
func (mr *MockTransactionalMockRecorder) BeginTX(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginTX", reflect.TypeOf((*MockTransactional)(nil).BeginTX), ctx)
}

// Commit mocks base method.
func (m *MockTransactional) Commit(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Commit", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Commit indicates an expected call of Commit.
func (mr *MockTransactionalMockRecorder) Commit(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockTransactional)(nil).Commit), ctx)
}

// Rollback mocks base method.
func (m *MockTransactional) Rollback(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Rollback", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Rollback indicates an expected call of Rollback.
func (mr *MockTransactionalMockRecorder) Rollback(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rollback", reflect.TypeOf((*MockTransactional)(nil).Rollback), ctx)
}
