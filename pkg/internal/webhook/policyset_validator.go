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
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

type policySetValidator struct{}

var _ admission.Validator[*policyapi.CertificateRequestPolicySet] = &policySetValidator{}

func (v *policySetValidator) ValidateCreate(_ context.Context, set *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	return nil, v.validate(set)
}

func (v *policySetValidator) ValidateUpdate(_ context.Context, _, set *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	return nil, v.validate(set)
}

func (v *policySetValidator) ValidateDelete(_ context.Context, _ *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	return nil, nil
}

func (v *policySetValidator) validate(set *policyapi.CertificateRequestPolicySet) error {
	fldPath := field.NewPath("spec")
	var errs field.ErrorList
	if set.Spec.Selector == nil {
		errs = append(errs, field.Required(fldPath.Child("selector"), "one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"))
		return errs.ToAggregate()
	}
	if set.Spec.Selector.IssuerRef == nil && set.Spec.Selector.Namespace == nil {
		errs = append(errs, field.Required(fldPath.Child("selector"), "one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"))
	}
	if nsSel := set.Spec.Selector.Namespace; nsSel != nil && len(nsSel.MatchLabels) > 0 {
		if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSel.MatchLabels}); err != nil {
			errs = append(errs, field.Invalid(fldPath.Child("selector", "namespace", "matchLabels"), nsSel.MatchLabels, err.Error()))
		}
	}
	return errs.ToAggregate()
}
