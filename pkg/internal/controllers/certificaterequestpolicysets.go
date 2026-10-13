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
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/controllers/ssa_client"
)

type certificaterequestpolicysets struct {
	log      logr.Logger
	clock    clock.Clock
	recorder events.EventRecorder
	client   client.Client
}

func addCertificateRequestPolicySetController(_ context.Context, opts Options) error {
	reconciler := &certificaterequestpolicysets{
		log:      opts.Log.WithName("certificaterequestpolicysets"),
		clock:    clock.RealClock{},
		recorder: opts.Manager.GetEventRecorder("policy.cert-manager.io"),
		client:   opts.Manager.GetClient(),
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.CertificateRequestPolicySetMaxConcurrentReconciles}).
		For(new(policyapi.CertificateRequestPolicySet)).
		Watches(
			new(policyapi.CertificateRequestPolicy),
			handler.EnqueueRequestsFromMapFunc(reconciler.policySetsForPolicy),
		).
		Complete(reconciler)
}

func (c *certificaterequestpolicysets) policySetsForPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
	policy := obj.(*policyapi.CertificateRequestPolicy)
	names := make(map[string]struct{})
	if policy.Spec.PolicySetRef != nil {
		names[policy.Spec.PolicySetRef.Name] = struct{}{}
	}

	var sets policyapi.CertificateRequestPolicySetList
	if err := c.client.List(ctx, &sets); err != nil {
		c.log.Error(err, "failed to list CertificateRequestPolicySets for policy event", "policy", policy.Name)
		return nil
	}
	for _, set := range sets.Items {
		for _, member := range set.Spec.Policies {
			if member.Name == policy.Name {
				names[set.Name] = struct{}{}
				break
			}
		}
	}

	requests := make([]reconcile.Request, 0, len(names))
	for name := range names {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].Name < requests[j].Name
	})
	return requests
}

func (c *certificaterequestpolicysets) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	status, resultErr := c.reconcileStatus(ctx, req)
	if status == nil {
		return ctrl.Result{}, resultErr
	}

	policySet, patch, err := ssa_client.GenerateCertificateRequestPolicySetStatusPatch(req.Name, status)
	if err != nil {
		return ctrl.Result{}, utilerrors.NewAggregate([]error{
			resultErr,
			fmt.Errorf("failed to generate CertificateRequestPolicySet.Status patch: %w", err),
		})
	}

	if err := c.client.Status().Patch(ctx, policySet, patch, &client.SubResourcePatchOptions{
		PatchOptions: client.PatchOptions{
			FieldManager: "approver-policy",
			Force:        new(true),
		},
	}); err != nil {
		return ctrl.Result{}, utilerrors.NewAggregate([]error{
			resultErr,
			fmt.Errorf("failed to apply CertificateRequestPolicySet.Status patch: %w", err),
		})
	}

	return ctrl.Result{}, resultErr
}

func (c *certificaterequestpolicysets) reconcileStatus(ctx context.Context, req ctrl.Request) (*policyapi.CertificateRequestPolicySetStatus, error) {
	policySet := new(policyapi.CertificateRequestPolicySet)
	if err := c.client.Get(ctx, req.NamespacedName, policySet); err != nil {
		return nil, client.IgnoreNotFound(err)
	}

	status := &policyapi.CertificateRequestPolicySetStatus{}
	var blockers []string
	for _, member := range policySet.Spec.Policies {
		memberStatus, err := c.memberStatus(ctx, policySet.Name, member.Name)
		if err != nil {
			return nil, err
		}
		status.Members = append(status.Members, memberStatus)
		if memberStatus.Ready == nil || !*memberStatus.Ready {
			blockers = append(blockers, fmt.Sprintf("%s: %s", member.Name, memberStatus.Message))
		}
	}
	sort.Slice(status.Members, func(i, j int) bool {
		return status.Members[i].Name < status.Members[j].Name
	})
	sort.Strings(blockers)

	condition := metav1.Condition{
		Type:               policyapi.ConditionTypeReady,
		ObservedGeneration: policySet.Generation,
		LastTransitionTime: metav1.Time{Time: c.clock.Now()},
	}
	if len(blockers) > 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "MembersNotReady"
		condition.Message = fmt.Sprintf("CertificateRequestPolicySet is not ready: %s", strings.Join(blockers, "; "))
		c.recorder.Eventf(policySet, nil, "Warning", "NotReady", "Synced", "%s", condition.Message)
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Ready"
		condition.Message = "CertificateRequestPolicySet is ready for evaluation"
		c.recorder.Eventf(policySet, nil, "Normal", "Ready", "Synced", "%s", condition.Message)
	}

	if policySet.Status != nil {
		if existing := meta.FindStatusCondition(policySet.Status.Conditions, policyapi.ConditionTypeReady); existing != nil &&
			existing.Status == condition.Status {
			condition.LastTransitionTime = existing.LastTransitionTime
		}
	}
	meta.SetStatusCondition(&status.Conditions, condition)
	return status, nil
}

func (c *certificaterequestpolicysets) memberStatus(
	ctx context.Context,
	setName string,
	policyName string,
) (policyapi.CertificateRequestPolicySetMemberStatus, error) {
	readyStatus := false
	status := policyapi.CertificateRequestPolicySetMemberStatus{
		Name:  policyName,
		Ready: &readyStatus,
	}
	policy := new(policyapi.CertificateRequestPolicy)
	if err := c.client.Get(ctx, client.ObjectKey{Name: policyName}, policy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			status.Reason = "Missing"
			status.Message = "policy does not exist"
			return status, nil
		}
		return status, fmt.Errorf("failed to get CertificateRequestPolicy %q: %w", policyName, err)
	}

	status.Generation = &policy.Generation
	if !policy.DeletionTimestamp.IsZero() {
		status.Reason = "Deleting"
		status.Message = "policy is deleting"
		return status, nil
	}
	if policy.Spec.PolicySetRef == nil || policy.Spec.PolicySetRef.Name != setName {
		status.Reason = "ReferenceMismatch"
		status.Message = fmt.Sprintf("policy does not reference set %q", setName)
		return status, nil
	}

	ready := meta.FindStatusCondition(policy.Status.Conditions, policyapi.ConditionTypeReady)
	if ready == nil {
		status.Reason = "ReadyConditionMissing"
		status.Message = "policy has no Ready condition"
		return status, nil
	}
	status.ObservedGeneration = &ready.ObservedGeneration
	if ready.ObservedGeneration != policy.Generation {
		status.Reason = "StaleGeneration"
		status.Message = fmt.Sprintf("policy Ready condition observed generation %d, current generation is %d", ready.ObservedGeneration, policy.Generation)
		return status, nil
	}
	if ready.Status != metav1.ConditionTrue {
		status.Reason = "NotReady"
		status.Message = fmt.Sprintf("policy Ready condition is %s", ready.Status)
		return status, nil
	}

	readyStatus = true
	status.Reason = "Ready"
	status.Message = "policy is ready"
	return status, nil
}
