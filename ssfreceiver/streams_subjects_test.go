// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
	"authelia.com/provider/oauth2/token/jwt"
)

// testSubjectCall is an add or a remove of a subject of the stream.
type testSubjectCall struct {
	name     string
	path     string
	endpoint string
	call     func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer, streamID string, subject *jwt.SubjectIdentifier) (err error)
}

func testSubjectCalls() []testSubjectCall {
	return []testSubjectCall{
		{
			name:     "Add",
			path:     testAddPath,
			endpoint: "add_subject_endpoint",
			call: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer, streamID string, subject *jwt.SubjectIdentifier) (err error) {
				return receiver.AddSubject(ctx, issuer, streamID, subject, nil)
			},
		},
		{
			name:     "Remove",
			path:     testRemovePath,
			endpoint: "remove_subject_endpoint",
			call: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer, streamID string, subject *jwt.SubjectIdentifier) (err error) {
				return receiver.RemoveSubject(ctx, issuer, streamID, subject)
			},
		},
	}
}

func newTestSubjectTransmitter(t *testing.T) *testStreamTransmitter {
	t.Helper()

	tx := newTestStreamTransmitter(t)

	tx.metadata = map[string]any{"add_subject_endpoint": tx.URL + testAddPath, "remove_subject_endpoint": tx.URL + testRemovePath}

	return tx
}

func testEmailSubject() *jwt.SubjectIdentifier {
	return &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail, Email: "example.user@example.com"}
}

const testEmailSubjectJSON = `{"format":"email","email":"example.user@example.com"}`

func TestReceiverStreamSubjects(t *testing.T) {
	for _, st := range testStores() {
		for _, sc := range testSubjectCalls() {
			t.Run(st.name+"/"+sc.name, func(t *testing.T) {
				t.Run("ShouldSendStreamIDAndSubject", func(t *testing.T) {
					testCases := []struct {
						name    string
						subject *jwt.SubjectIdentifier
						body    string
					}{
						{"ShouldSendEmailSubject", testEmailSubject(), testEmailSubjectJSON},
						{
							"ShouldSendIssuerAndSubject",
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatIssuerSubject, Issuer: "https://idp.example.com", Subject: "user-1"},
							`{"format":"iss_sub","iss":"https://idp.example.com","sub":"user-1"}`,
						},
						{
							"ShouldSendComplexSubject",
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: jwt.SubjectIdentifierComplexMembers{
								Tenant: &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatOpaque, ID: "example-a38h4792-uw2"},
							}},
							`{"format":"complex","tenant":{"format":"opaque","id":"example-a38h4792-uw2"}}`,
						},
						{
							"ShouldSendOnlyMembersOfFormat",
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail, Email: "example.user@example.com", ID: "other"},
							testEmailSubjectJSON,
						},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestSubjectTransmitter(t)
							receiver := tx.receiver(st)

							tx.answer(http.StatusOK, nil)

							require.NoError(t, sc.call(t.Context(), receiver, tx.URL, testStreamID, tc.subject))

							require.Len(t, tx.received(), 1)

							call := tx.received()[0]

							assert.Equal(t, sc.path, call.path)
							assert.Equal(t, http.MethodPost, call.method)
							assert.Empty(t, call.query)
							assert.Equal(t, "application/json", call.contentType)
							assert.Equal(t, "Bearer "+testStreamToken, call.authorization)
							assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","subject":`+tc.body+`}`, call.body)
							assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

							// The subjects of a stream are not stored.
							requireNoStreamRecords(t, receiver.Store, tx.URL)
						})
					}
				})

				t.Run("ShouldAcceptAny2xx", func(t *testing.T) {
					for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
						t.Run(http.StatusText(status), func(t *testing.T) {
							tx := newTestSubjectTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							// The body of the response is not read as anything.
							tx.on(func(w http.ResponseWriter, _ testStreamCall) {
								w.WriteHeader(status)

								if status != http.StatusNoContent {
									_, _ = w.Write([]byte("ok"))
								}
							})

							require.NoError(t, sc.call(t.Context(), receiver, tx.URL, testStreamID, testEmailSubject()))

							require.Len(t, tx.received(), 1)

							requireStreamRecord(t, receiver.Store, record)
						})
					}
				})

				t.Run("ShouldSendWithoutStore", func(t *testing.T) {
					tx := newTestSubjectTransmitter(t)
					receiver := tx.receiver(st)
					receiver.Store = nil

					tx.answer(http.StatusNoContent, nil)

					require.NoError(t, sc.call(t.Context(), receiver, tx.URL, testStreamID, testEmailSubject()))

					require.Len(t, tx.received(), 1)
				})

				t.Run("ShouldReturnTransmitterError", func(t *testing.T) {
					testCases := []struct {
						name     string
						status   int
						expected error
					}{
						{"ShouldReturnErrorOn400", http.StatusBadRequest, nil},
						{"ShouldReturnUnauthorizedOn401", http.StatusUnauthorized, ssfreceiver.ErrTransmitterUnauthorized},
						{"ShouldReturnForbiddenOn403", http.StatusForbidden, ssfreceiver.ErrTransmitterForbidden},
						{"ShouldReturnNotFoundOn404", http.StatusNotFound, ssfreceiver.ErrStreamNotFound},
						{"ShouldReturnThrottledOn429", http.StatusTooManyRequests, ssfreceiver.ErrTransmitterThrottled},
						{"ShouldReturnErrorOn500", http.StatusInternalServerError, nil},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestSubjectTransmitter(t)
							receiver := tx.receiver(st)

							tx.on(func(w http.ResponseWriter, _ testStreamCall) {
								w.Header().Set("Retry-After", "30")
								w.WriteHeader(tc.status)
							})

							err := sc.call(t.Context(), receiver, tx.URL, testStreamID, testEmailSubject())

							var e *ssfreceiver.TransmitterError

							require.ErrorAs(t, err, &e)
							assert.Equal(t, tc.status, e.Status)
							assert.Equal(t, 30*time.Second, e.RetryAfter)

							if tc.expected != nil {
								require.ErrorIs(t, err, tc.expected)
							}

							// A POST is not sent again.
							assert.Len(t, tx.received(), 1)
						})
					}
				})

				t.Run("ShouldValidateSubjectBeforeSending", func(t *testing.T) {
					testCases := []struct {
						name     string
						streamID string
						subject  *jwt.SubjectIdentifier
						invalid  bool
					}{
						{"ShouldRequireStreamID", "", testEmailSubject(), false},
						{"ShouldRequireSubject", testStreamID, nil, true},
						{"ShouldRequireFormat", testStreamID, &jwt.SubjectIdentifier{Email: "example.user@example.com"}, true},
						{"ShouldRequireMemberOfFormat", testStreamID, &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail, ID: "user-1"}, true},
						{"ShouldRejectEmailWithoutDomain", testStreamID, &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail, Email: "example.user"}, true},
						{"ShouldRejectPhoneNumberWithoutPrefix", testStreamID, &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatPhoneNumber, PhoneNumber: "12065550123"}, true},
						{"ShouldRejectComplexWithoutMembers", testStreamID, &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex}, true},
						{
							"ShouldRejectInvalidComplexMember", testStreamID,
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: jwt.SubjectIdentifierComplexMembers{
								User: &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail},
							}},
							true,
						},
						// A format which is not defined has no members that are sent.
						{"ShouldRejectFormatNotDefined", testStreamID, &jwt.SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"item_id": "1"}}, true},
						// SSF Sections 3.3.1 and 8.1.3.1: a member that is not sent would widen the subject.
						{"ShouldRejectAdditionalMember", testStreamID, &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatEmail, Email: "example.user@example.com", Additional: map[string]any{"workspace": "a"}}, false},
						{
							"ShouldRejectComplexWithAdditionalMember", testStreamID,
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: jwt.SubjectIdentifierComplexMembers{
								User: testEmailSubject(),
							}, Additional: map[string]any{"workspace": map[string]any{"format": "opaque", "id": "a"}}},
							false,
						},
						{
							"ShouldRejectAliasWithAdditionalMember", testStreamID,
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatAliases, Identifiers: []jwt.SubjectIdentifier{
								*testEmailSubject(), {Format: jwt.SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"region": "eu"}},
							}},
							false,
						},
						{
							"ShouldRejectAliasOfComplexMemberWithAdditionalMember", testStreamID,
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: jwt.SubjectIdentifierComplexMembers{
								User: &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatAliases, Identifiers: []jwt.SubjectIdentifier{
									*testEmailSubject(), {Format: jwt.SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"region": "eu"}},
								}},
							}},
							false,
						},
						{
							"ShouldRejectNestedAdditionalMember", testStreamID,
							&jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: jwt.SubjectIdentifierComplexMembers{
								Tenant: &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatOpaque, ID: "t", Additional: map[string]any{"region": "eu"}},
							}},
							false,
						},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestSubjectTransmitter(t)
							receiver := tx.receiver(st)

							tx.answer(http.StatusOK, nil)

							err := sc.call(t.Context(), receiver, tx.URL, tc.streamID, tc.subject)

							require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)

							if tc.invalid {
								require.ErrorIs(t, err, jwt.ErrInvalidSubjectIdentifier)
							}

							assert.Empty(t, tx.received())
							assert.Empty(t, tx.requestedScopes())
						})
					}
				})

				t.Run("ShouldReturnNotSupportedWithoutEndpoint", func(t *testing.T) {
					tx := newTestSubjectTransmitter(t)

					// SSF Section 7.1: the endpoint is optional. The other one does not stand in for it.
					tx.metadata[sc.endpoint] = nil

					receiver := tx.receiver(st)

					tx.answer(http.StatusOK, nil)

					require.ErrorIs(t, sc.call(t.Context(), receiver, tx.URL, testStreamID, testEmailSubject()), ssfreceiver.ErrEndpointNotSupported)

					assert.Empty(t, tx.received())
					assert.Empty(t, tx.requestedScopes())
				})

				t.Run("ShouldRefuseUnderProfile", func(t *testing.T) {
					tx := newTestSubjectTransmitter(t)
					receiver := tx.receiver(st)
					receiver.Config.EnforceCAEPInteroperabilityProfile = true

					tx.answer(http.StatusOK, nil)

					require.ErrorIs(t, sc.call(t.Context(), receiver, tx.URL, testStreamID, testEmailSubject()), ssfreceiver.ErrSubjectsImplicit)

					assert.Empty(t, tx.received())
					assert.Empty(t, tx.requestedScopes())

					// It is refused before the metadata is requested, which this issuer has none of.
					require.ErrorIs(t, sc.call(t.Context(), receiver, "http://tx.example.com", testStreamID, testEmailSubject()), ssfreceiver.ErrSubjectsImplicit)

					// The subject is not looked at.
					require.ErrorIs(t, sc.call(t.Context(), receiver, tx.URL, "", nil), ssfreceiver.ErrSubjectsImplicit)
				})
			})
		}
	}
}

func TestReceiverAddSubjectVerified(t *testing.T) {
	yes, no := true, false

	testCases := []struct {
		name     string
		verified *bool
		body     string
	}{
		{"ShouldOmitVerifiedWhenUnset", nil, `{"stream_id":"` + testStreamID + `","subject":` + testEmailSubjectJSON + `}`},
		{"ShouldSendVerifiedTrue", &yes, `{"stream_id":"` + testStreamID + `","subject":` + testEmailSubjectJSON + `,"verified":true}`},
		{"ShouldSendVerifiedFalse", &no, `{"stream_id":"` + testStreamID + `","subject":` + testEmailSubjectJSON + `,"verified":false}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTestSubjectTransmitter(t)
			receiver := tx.receiver(testStores()[0])

			tx.answer(http.StatusOK, nil)

			require.NoError(t, receiver.AddSubject(t.Context(), tx.URL, testStreamID, testEmailSubject(), tc.verified))

			require.Len(t, tx.received(), 1)
			assert.Equal(t, testAddPath, tx.received()[0].path)
			assert.JSONEq(t, tc.body, tx.received()[0].body)
			assert.Equal(t, tc.verified != nil, containsVerified(tx.received()[0].body))
		})
	}
}

func TestReceiverAddSubjectFollowsOnlyMembersOfFormat(t *testing.T) {
	tx := newTestSubjectTransmitter(t)
	receiver := tx.receiver(testStores()[0])

	tx.answer(http.StatusOK, nil)

	// The complex members of an email subject are not sent, so they are neither followed nor checked.
	subject := testEmailSubject()
	subject.User = subject
	subject.Device = &jwt.SubjectIdentifier{Format: jwt.SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"region": "eu"}}

	require.NoError(t, receiver.AddSubject(t.Context(), tx.URL, testStreamID, subject, nil))

	require.Len(t, tx.received(), 1)
	assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","subject":`+testEmailSubjectJSON+`}`, tx.received()[0].body)
}

func containsVerified(body string) (ok bool) {
	var members map[string]json.RawMessage

	if json.Unmarshal([]byte(body), &members) != nil {
		return false
	}

	_, ok = members["verified"]

	return ok
}

// TestReceiverInteroperabilityProfileSubjects has the subject half of the CAEP Interoperability Profile requirements.
func TestReceiverInteroperabilityProfileSubjects(t *testing.T) {
	testCases := []struct {
		name string
		call func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (err error)
	}{
		{"ShouldRefuseAddSubjectUnderProfile", func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (err error) {
			return receiver.AddSubject(ctx, issuer, testStreamID, testEmailSubject(), nil)
		}},
		{"ShouldRefuseRemoveSubjectUnderProfile", func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (err error) {
			return receiver.RemoveSubject(ctx, issuer, testStreamID, testEmailSubject())
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTestSubjectTransmitter(t)
			receiver := tx.receiver(testStores()[0])

			tx.answer(http.StatusOK, nil)

			// Profile Section 2.4.4: every subject is implicitly in the stream.
			receiver.Config.EnforceCAEPInteroperabilityProfile = true

			require.ErrorIs(t, tc.call(t.Context(), receiver, tx.URL), ssfreceiver.ErrSubjectsImplicit)
			assert.Empty(t, tx.received())
			assert.Empty(t, tx.requestedScopes())

			receiver.Config.EnforceCAEPInteroperabilityProfile = false

			require.NoError(t, tc.call(t.Context(), receiver, tx.URL))
			assert.Len(t, tx.received(), 1)
		})
	}
}
