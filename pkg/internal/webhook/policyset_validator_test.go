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

package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

func TestPolicySetValidator(t *testing.T) {
	tests := map[string]struct {
		selector      policyapi.CertificateRequestPolicySelector
		expectedError string
	}{
		"issuer selector is valid": {
			selector: policyapi.CertificateRequestPolicySelector{
				IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
			},
		},
		"namespace selector is valid": {
			selector: policyapi.CertificateRequestPolicySelector{
				Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{},
			},
		},
		"selector is required": {
			expectedError: "spec.selector: Required value: one of issuerRef or namespace must be defined",
		},
		"namespace labels must be valid": {
			selector: policyapi.CertificateRequestPolicySelector{
				Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
					MatchLabels: map[string]string{"$invalid": "value"},
				},
			},
			expectedError: "spec.selector.namespace.matchLabels: Invalid value",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := (&policySetValidator{}).validate(&policyapi.CertificateRequestPolicySet{
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Selector: &test.selector,
					Policies: []policyapi.CertificateRequestPolicySetMember{{Name: "allow"}},
				},
			})

			if test.expectedError == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, test.expectedError)
		})
	}
}
