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

package ssa_client

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

type certificateRequestPolicySetStatusApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *policyapi.CertificateRequestPolicySetStatus `json:"status,omitempty"`
}

func GenerateCertificateRequestPolicySetStatusPatch(
	name string,
	status *policyapi.CertificateRequestPolicySetStatus,
) (*policyapi.CertificateRequestPolicySet, client.Patch, error) {
	policySet := &policyapi.CertificateRequestPolicySet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}

	b := &certificateRequestPolicySetStatusApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
	}
	b.WithName(name)
	b.WithKind(policyapi.CertificateRequestPolicySetKind)
	b.WithAPIVersion(policyapi.SchemeGroupVersion.Identifier())
	b.Status = status

	encodedPatch, err := json.Marshal(b)
	if err != nil {
		return policySet, nil, err
	}

	return policySet, applyPatch{encodedPatch}, nil
}
