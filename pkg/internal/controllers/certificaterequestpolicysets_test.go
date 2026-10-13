/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	fakeclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

func TestCertificateRequestPolicySetStatus(t *testing.T) {
	const setName = "platform"
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		objects        []client.Object
		expectedReady  metav1.ConditionStatus
		expectedReason string
		memberReasons  map[string]string
	}{
		"all members ready": {
			objects: []client.Object{
				testPolicySet("allow", "deny"),
				testReadySetPolicy("allow", setName),
				testReadySetPolicy("deny", setName),
			},
			expectedReady:  metav1.ConditionTrue,
			expectedReason: "Ready",
			memberReasons:  map[string]string{"allow": "Ready", "deny": "Ready"},
		},
		"missing member": {
			objects: []client.Object{
				testPolicySet("allow", "deny"),
				testReadySetPolicy("deny", setName),
			},
			expectedReady:  metav1.ConditionFalse,
			expectedReason: "MembersNotReady",
			memberReasons:  map[string]string{"allow": "Missing", "deny": "Ready"},
		},
		"stale member generation": {
			objects: []client.Object{
				testPolicySet("allow"),
				testStaleSetPolicy("allow", setName),
			},
			expectedReady:  metav1.ConditionFalse,
			expectedReason: "MembersNotReady",
			memberReasons:  map[string]string{"allow": "StaleGeneration"},
		},
		"member references another set": {
			objects: []client.Object{
				testPolicySet("allow"),
				testReadySetPolicy("allow", "another"),
			},
			expectedReady:  metav1.ConditionFalse,
			expectedReason: "MembersNotReady",
			memberReasons:  map[string]string{"allow": "ReferenceMismatch"},
		},
		"member is deleting": {
			objects: []client.Object{
				testPolicySet("allow"),
				testDeletingSetPolicy("allow", setName),
			},
			expectedReady:  metav1.ConditionFalse,
			expectedReason: "MembersNotReady",
			memberReasons:  map[string]string{"allow": "Deleting"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, policyapi.AddToScheme(scheme))
			fakeClient := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(test.objects...).
				Build()
			controller := &certificaterequestpolicysets{
				log:      log.Log,
				clock:    fakeclock.NewFakeClock(now),
				recorder: events.NewFakeRecorder(10),
				client:   fakeClient,
			}

			status, err := controller.reconcileStatus(t.Context(), reconcile.Request{
				NamespacedName: types.NamespacedName{Name: setName},
			})
			require.NoError(t, err)
			require.NotNil(t, status)
			require.Len(t, status.Conditions, 1)
			assert.Equal(t, test.expectedReady, status.Conditions[0].Status)
			assert.Equal(t, test.expectedReason, status.Conditions[0].Reason)
			assert.Equal(t, metav1.NewTime(now), status.Conditions[0].LastTransitionTime)

			actualReasons := make(map[string]string, len(status.Members))
			for _, member := range status.Members {
				actualReasons[member.Name] = member.Reason
			}
			assert.Equal(t, test.memberReasons, actualReasons)
		})
	}
}

func testPolicySet(members ...string) *policyapi.CertificateRequestPolicySet {
	set := &policyapi.CertificateRequestPolicySet{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Generation: 1},
		Spec: policyapi.CertificateRequestPolicySetSpec{
			Selector: &policyapi.CertificateRequestPolicySelector{
				IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
			},
		},
	}
	for _, member := range members {
		set.Spec.Policies = append(set.Spec.Policies, policyapi.CertificateRequestPolicySetMember{Name: member})
	}
	return set
}

func testReadySetPolicy(name, setName string) *policyapi.CertificateRequestPolicy {
	return &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 2},
		Spec: policyapi.CertificateRequestPolicySpec{
			PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: setName},
		},
		Status: policyapi.CertificateRequestPolicyStatus{
			Conditions: []metav1.Condition{{
				Type:               policyapi.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 2,
			}},
		},
	}
}

func testStaleSetPolicy(name, setName string) *policyapi.CertificateRequestPolicy {
	policy := testReadySetPolicy(name, setName)
	policy.Status.Conditions[0].ObservedGeneration = 1
	return policy
}

func testDeletingSetPolicy(name, setName string) *policyapi.CertificateRequestPolicy {
	policy := testReadySetPolicy(name, setName)
	policy.Finalizers = []string{"test"}
	policy.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	return policy
}
