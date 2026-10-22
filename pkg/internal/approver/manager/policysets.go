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
	"fmt"
	"sort"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/manager/predicate"
)

type policySetSelection struct {
	policies   []policyapi.CertificateRequestPolicy
	incomplete []string
}

type policyAuthorizationFunc func(context.Context, *cmapi.CertificateRequest, string, string) (bool, error)

func (m *mngr) selectPolicySetMembers(
	ctx context.Context,
	request *cmapi.CertificateRequest,
	allPolicies []policyapi.CertificateRequestPolicy,
	sets []policyapi.CertificateRequestPolicySet,
) (policySetSelection, error) {
	policiesByName := make(map[string]policyapi.CertificateRequestPolicy, len(allPolicies))
	for _, policy := range allPolicies {
		policiesByName[policy.Name] = policy
	}

	var selection policySetSelection
	for _, set := range sets {
		applicable, err := m.policySetApplicable(ctx, request, set)
		if err != nil {
			return policySetSelection{}, fmt.Errorf("failed to determine whether CertificateRequestPolicySet %q is applicable: %w", set.Name, err)
		}
		if !applicable {
			continue
		}

		bound, err := m.authorize(ctx, request, "certificaterequestpolicysets", set.Name)
		if err != nil {
			return policySetSelection{}, fmt.Errorf("failed to determine CertificateRequestPolicySet %q authorization: %w", set.Name, err)
		}
		if !bound {
			continue
		}

		members, blockers, err := m.completePolicySetMembers(ctx, request, set, policiesByName)
		if err != nil {
			return policySetSelection{}, err
		}
		if len(blockers) > 0 {
			sort.Strings(blockers)
			selection.incomplete = append(selection.incomplete, fmt.Sprintf("%s (%s)", set.Name, strings.Join(blockers, "; ")))
			continue
		}

		members, err = predicate.SelectorIssuerRef(ctx, request, members)
		if err != nil {
			return policySetSelection{}, err
		}
		members, err = predicate.SelectorNamespace(m.reader)(ctx, request, members)
		if err != nil {
			return policySetSelection{}, err
		}
		selection.policies = append(selection.policies, members...)
	}

	sort.Strings(selection.incomplete)
	return selection, nil
}

func (m *mngr) policySetApplicable(
	ctx context.Context,
	request *cmapi.CertificateRequest,
	set policyapi.CertificateRequestPolicySet,
) (bool, error) {
	if set.Spec.Selector == nil {
		return false, nil
	}
	synthetic := []policyapi.CertificateRequestPolicy{{
		Spec: policyapi.CertificateRequestPolicySpec{Selector: *set.Spec.Selector},
	}}

	matching, err := predicate.SelectorIssuerRef(ctx, request, synthetic)
	if err != nil || len(matching) == 0 {
		return false, err
	}
	matching, err = predicate.SelectorNamespace(m.reader)(ctx, request, matching)
	return len(matching) > 0, err
}

func (m *mngr) completePolicySetMembers(
	ctx context.Context,
	request *cmapi.CertificateRequest,
	set policyapi.CertificateRequestPolicySet,
	policiesByName map[string]policyapi.CertificateRequestPolicy,
) ([]policyapi.CertificateRequestPolicy, []string, error) {
	members := make([]policyapi.CertificateRequestPolicy, 0, len(set.Spec.Policies))
	var blockers []string
	for _, expected := range set.Spec.Policies {
		policy, ok := policiesByName[expected.Name]
		if !ok {
			blockers = append(blockers, fmt.Sprintf("%s is missing", expected.Name))
			continue
		}
		if !policy.DeletionTimestamp.IsZero() {
			blockers = append(blockers, fmt.Sprintf("%s is deleting", expected.Name))
			continue
		}
		if policy.Spec.PolicySetRef == nil || policy.Spec.PolicySetRef.Name != set.Name {
			blockers = append(blockers, fmt.Sprintf("%s does not reference the set", expected.Name))
			continue
		}

		ready := false
		for _, condition := range policy.Status.Conditions {
			if condition.Type == policyapi.ConditionTypeReady &&
				condition.Status == metav1.ConditionTrue &&
				condition.ObservedGeneration == policy.Generation {
				ready = true
				break
			}
		}
		if !ready {
			blockers = append(blockers, fmt.Sprintf("%s is not ready for its current generation", expected.Name))
			continue
		}

		bound, err := m.authorize(ctx, request, "certificaterequestpolicies", policy.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to determine CertificateRequestPolicy %q authorization: %w", policy.Name, err)
		}
		if !bound {
			blockers = append(blockers, fmt.Sprintf("%s is not authorized", expected.Name))
			continue
		}

		members = append(members, policy)
	}
	return members, blockers, nil
}
