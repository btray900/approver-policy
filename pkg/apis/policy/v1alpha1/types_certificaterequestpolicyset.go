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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

var CertificateRequestPolicySetKind = "CertificateRequestPolicySet"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type == "Ready")].status`,description="CertificateRequestPolicySet is ready for evaluation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Timestamp CertificateRequestPolicySet was created"
//+kubebuilder:resource:categories=cert-manager,shortName=crps,scope=Cluster
//+kubebuilder:subresource:status

// CertificateRequestPolicySet coordinates a complete set of
// CertificateRequestPolicies so its members are evaluated only after every
// expected policy is ready for its current generation.
type CertificateRequestPolicySet struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata"`

	// spec is the desired state of the CertificateRequestPolicySet.
	// +required
	Spec CertificateRequestPolicySetSpec `json:"spec,omitzero"`
	// status is the observed state of the CertificateRequestPolicySet.
	// +optional
	Status *CertificateRequestPolicySetStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// CertificateRequestPolicySetList is a list of CertificateRequestPolicySets.
type CertificateRequestPolicySetList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata"`

	Items []CertificateRequestPolicySet `json:"items"`
}

// CertificateRequestPolicySetSpec defines the desired members and request
// scope of a CertificateRequestPolicySet.
type CertificateRequestPolicySetSpec struct {
	// selector determines which CertificateRequests can be affected by an
	// incomplete set. It is independent of member policy availability so the
	// manager can defer terminal decisions while members are still arriving.
	// +required
	Selector *CertificateRequestPolicySelector `json:"selector,omitempty"`

	// policies lists the exact CertificateRequestPolicies that form this set.
	// Every listed policy must reference this set through spec.policySetRef.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	Policies []CertificateRequestPolicySetMember `json:"policies,omitempty"`
}

// CertificateRequestPolicySetMember identifies an expected policy.
type CertificateRequestPolicySetMember struct {
	// name is the name of an expected CertificateRequestPolicy.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
}

// CertificateRequestPolicySetStatus defines the observed collective readiness
// of a CertificateRequestPolicySet.
type CertificateRequestPolicySetStatus struct {
	// conditions reports the collective readiness of the set.
	// Known condition types are `Ready`.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` //nolint:tagalign // Kubernetes API conventions require this tag order.

	// members reports readiness details for each expected policy.
	// +listType=map
	// +listMapKey=name
	// +optional
	Members []CertificateRequestPolicySetMemberStatus `json:"members,omitempty"`
}

// CertificateRequestPolicySetMemberStatus reports why an expected policy is
// or is not ready to participate in evaluation.
type CertificateRequestPolicySetMemberStatus struct {
	// name is the expected policy name.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`

	// ready indicates whether the member exists, references this set, is not
	// deleting, and has a current Ready=True condition.
	// +required
	Ready *bool `json:"ready,omitempty"`

	// reason is a machine readable readiness reason.
	// +required
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason,omitempty"`

	// message explains the member readiness result.
	// +required
	// +kubebuilder:validation:MinLength=1
	Message string `json:"message,omitempty"`

	// generation is the current policy generation when the policy exists.
	// +optional
	Generation *int64 `json:"generation,omitempty"`

	// observedGeneration is the generation observed by the member Ready
	// condition, when present.
	// +optional
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
}
