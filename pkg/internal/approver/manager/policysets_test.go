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

package manager

import (
	"context"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	approverfake "github.com/cert-manager/approver-policy/pkg/approver/fake"
	approvermanager "github.com/cert-manager/approver-policy/pkg/approver/manager"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/manager/predicate"
)

func TestReviewPolicySets(t *testing.T) {
	const setName = "platform"

	tests := map[string]struct {
		objects         []client.Object
		request         *cmapi.CertificateRequest
		authorized      func(resource, name string) bool
		evaluate        func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse
		expectedResult  approvermanager.ReviewResult
		expectedMessage string
		expectedCalls   []string
	}{
		"missing member defers terminal decisions": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				readySetPolicy("deny", setName),
			},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "policy sets are incomplete: platform (allow is missing)",
		},
		"stale member generation defers terminal decisions": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				staleSetPolicy("allow", setName),
				readySetPolicy("deny", setName),
			},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "allow is not ready for its current generation",
		},
		"member referencing another set defers terminal decisions": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				readySetPolicy("allow", "another-set"),
				readySetPolicy("deny", setName),
			},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "allow does not reference the set",
		},
		"unauthorized member defers terminal decisions": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				readySetPolicy("allow", setName),
				readySetPolicy("deny", setName),
			},
			authorized: func(resource, name string) bool {
				return resource != "certificaterequestpolicies" || name != "allow"
			},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "allow is not authorized",
		},
		"complete set can approve": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				readySetPolicy("allow", setName),
				readySetPolicy("deny", setName),
			},
			evaluate: func(policy *policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				if policy.Name == "allow" {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied}
				}
				return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "denied"}
			},
			expectedResult:  approvermanager.ResultApproved,
			expectedMessage: `Approved by CertificateRequestPolicy: "allow"`,
			expectedCalls:   []string{"allow"},
		},
		"complete set can deny": {
			objects: []client.Object{
				platformPolicySet("allow", "deny"),
				readySetPolicy("allow", setName),
				readySetPolicy("deny", setName),
			},
			evaluate: func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "denied"}
			},
			expectedResult:  approvermanager.ResultDenied,
			expectedMessage: "No policy approved this request",
			expectedCalls:   []string{"allow", "deny"},
		},
		"standalone approval wins while a set is incomplete": {
			objects: []client.Object{
				platformPolicySet("missing"),
				readyStandalonePolicy("standalone"),
			},
			evaluate: func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}
			},
			expectedResult:  approvermanager.ResultApproved,
			expectedMessage: `Approved by CertificateRequestPolicy: "standalone"`,
			expectedCalls:   []string{"standalone"},
		},
		"complete set approval wins while another set is incomplete": {
			objects: []client.Object{
				platformPolicySet("missing"),
				&policyapi.CertificateRequestPolicySet{
					ObjectMeta: metav1.ObjectMeta{Name: "independent"},
					Spec: policyapi.CertificateRequestPolicySetSpec{
						Selector: &policyapi.CertificateRequestPolicySelector{
							IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
						},
						Policies: []policyapi.CertificateRequestPolicySetMember{{Name: "allow"}},
					},
				},
				readySetPolicy("allow", "independent"),
			},
			evaluate: func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}
			},
			expectedResult:  approvermanager.ResultApproved,
			expectedMessage: `Approved by CertificateRequestPolicy: "allow"`,
			expectedCalls:   []string{"allow"},
		},
		"unauthorized set does not defer standalone denial": {
			objects: []client.Object{
				platformPolicySet("missing"),
				readyStandalonePolicy("deny"),
			},
			authorized: func(resource, _ string) bool {
				return resource != "certificaterequestpolicysets"
			},
			expectedResult:  approvermanager.ResultDenied,
			expectedMessage: "No policy approved this request",
			expectedCalls:   []string{"deny"},
		},
		"set namespace selector does not match": {
			objects: []client.Object{
				&policyapi.CertificateRequestPolicySet{
					ObjectMeta: metav1.ObjectMeta{Name: setName},
					Spec: policyapi.CertificateRequestPolicySetSpec{
						Selector: &policyapi.CertificateRequestPolicySelector{
							Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
								MatchNames: []string{"apps"},
							},
						},
						Policies: []policyapi.CertificateRequestPolicySetMember{{Name: "missing"}},
					},
				},
				readyStandalonePolicy("deny"),
			},
			request:         &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "other"}},
			expectedResult:  approvermanager.ResultDenied,
			expectedMessage: "No policy approved this request",
			expectedCalls:   []string{"deny"},
		},
		"member namespace selector remains enforced": {
			objects: []client.Object{
				platformPolicySet("allow"),
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "allow", Generation: 2},
					Spec: policyapi.CertificateRequestPolicySpec{
						PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: setName},
						Selector: policyapi.CertificateRequestPolicySelector{
							Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
								MatchNames: []string{"apps"},
							},
						},
					},
					Status: readySetPolicy("allow", setName).Status,
				},
			},
			request:         &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "other"}},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "No CertificateRequestPolicies bound or applicable",
		},
		"standalone readiness behavior is unchanged": {
			objects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "allow", Generation: 3},
					Status:     readyStandalonePolicy("allow").Status,
				},
			},
			evaluate: func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}
			},
			expectedResult:  approvermanager.ResultApproved,
			expectedMessage: `Approved by CertificateRequestPolicy: "allow"`,
			expectedCalls:   []string{"allow"},
		},
		"set member never falls back to standalone evaluation": {
			objects: []client.Object{
				readySetPolicy("orphan", "missing-set"),
				readyStandalonePolicy("deny"),
			},
			evaluate: func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
				return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "denied"}
			},
			expectedResult:  approvermanager.ResultDenied,
			expectedMessage: "No policy approved this request",
			expectedCalls:   []string{"deny"},
		},
		"set without policies still defers its matching requests": {
			objects: []client.Object{
				platformPolicySet("allow"),
			},
			expectedResult:  approvermanager.ResultUnprocessed,
			expectedMessage: "allow is missing",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, policyapi.AddToScheme(scheme))
			fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(test.objects...).Build()
			authorized := test.authorized
			if authorized == nil {
				authorized = func(string, string) bool { return true }
			}
			evaluate := test.evaluate
			if evaluate == nil {
				evaluate = func(*policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "denied"}
				}
			}
			var calls []string
			evaluator := approverfake.NewFakeEvaluator().WithEvaluate(func(
				_ context.Context,
				policy *policyapi.CertificateRequestPolicy,
				_ *cmapi.CertificateRequest,
			) (approver.EvaluationResponse, error) {
				calls = append(calls, policy.Name)
				return evaluate(policy), nil
			})
			manager := &mngr{
				reader: fakeClient,
				authorize: func(_ context.Context, _ *cmapi.CertificateRequest, resource, name string) (bool, error) {
					return authorized(resource, name), nil
				},
				readyPredicate: predicate.Ready,
				evaluators:     []approver.Evaluator{evaluator},
			}

			request := test.request
			if request == nil {
				request = &cmapi.CertificateRequest{}
			}
			response, err := manager.Review(t.Context(), request)
			require.NoError(t, err)
			assert.Equal(t, test.expectedResult, response.Result)
			assert.True(t, strings.Contains(response.Message, test.expectedMessage), response.Message)
			assert.Equal(t, test.expectedCalls, calls)
		})
	}
}

func platformPolicySet(members ...string) *policyapi.CertificateRequestPolicySet {
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

func readySetPolicy(name, setName string) *policyapi.CertificateRequestPolicy {
	policy := readyStandalonePolicy(name)
	policy.Spec.PolicySetRef = &policyapi.CertificateRequestPolicySetReference{Name: setName}
	return policy
}

func staleSetPolicy(name, setName string) *policyapi.CertificateRequestPolicy {
	policy := readySetPolicy(name, setName)
	policy.Status.Conditions[0].ObservedGeneration = policy.Generation - 1
	return policy
}

func readyStandalonePolicy(name string) *policyapi.CertificateRequestPolicy {
	return &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 2},
		Spec: policyapi.CertificateRequestPolicySpec{
			Selector: policyapi.CertificateRequestPolicySelector{},
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
