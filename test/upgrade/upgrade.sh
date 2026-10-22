#!/bin/bash
# Copyright 2026 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

: "${KUBECONFIG:?Use the dedicated Kind cluster configured by make test-upgrade}"
: "${HELM:?}"
: "${KUBECTL:?}"
: "${UPGRADE_CHART:?}"
: "${UPGRADE_IMAGE:?}"
: "${UPGRADE_TAG:?}"
: "${MANAGE_CRDS:?}"
case "${MANAGE_CRDS}" in
    true|false) ;;
    *) echo "MANAGE_CRDS must be true or false" >&2; exit 1 ;;
esac

legacy_version=v0.28.0
namespace=approver-policy-upgrade
scratch=$(mktemp -d)
legacy_chart="${scratch}/cert-manager-approver-policy-${legacy_version}.tgz"
trap 'rm -f -- "${legacy_chart}"; rmdir -- "${scratch}"' EXIT

"${HELM}" pull oci://quay.io/jetstack/charts/cert-manager-approver-policy \
    --version "${legacy_version}" --destination "${scratch}"

if [[ "${MANAGE_CRDS}" == false ]]; then
    "${HELM}" template upgrade-test "${legacy_chart}" \
        --show-only templates/crd-policy.cert-manager.io_certificaterequestpolicies.yaml |
        "${KUBECTL}" apply -f -
fi

"${HELM}" install upgrade-test "${legacy_chart}" \
    --namespace "${namespace}" --create-namespace --wait --timeout 180s \
    --set "crds.enabled=${MANAGE_CRDS}" \
    --set "image.tag=${legacy_version}"

"${KUBECTL}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: upgrade-test
  namespace: ${namespace}
spec:
  selfSigned: {}
---
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: upgrade-standalone
spec:
  allowed:
    commonName:
      value: "*.example.com"
    usages: ["digital signature"]
  selector:
    issuerRef:
      name: upgrade-test
    namespace:
      matchNames: ["${namespace}"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: upgrade-test-use
rules:
  - apiGroups: ["policy.cert-manager.io"]
    resources: ["certificaterequestpolicies", "certificaterequestpolicysets"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: upgrade-test-use
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: upgrade-test-use
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: system:serviceaccounts:cert-manager
EOF

issue_certificate() {
    local name=$1 issuer=$2
    "${KUBECTL}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  secretName: ${name}
  commonName: test.example.com
  usages: ["digital signature"]
  issuerRef:
    name: ${issuer}
    kind: Issuer
    group: cert-manager.io
EOF
}

issue_certificate before-upgrade upgrade-test
"${KUBECTL}" wait --namespace "${namespace}" --for=condition=Ready \
    certificate/before-upgrade --timeout=120s

if [[ "${MANAGE_CRDS}" == false ]]; then
    "${KUBECTL}" apply -f deploy/crds/policy.cert-manager.io_certificaterequestpolicies.yaml \
        -f deploy/crds/policy.cert-manager.io_certificaterequestpolicysets.yaml
    "${KUBECTL}" wait --for=condition=Established \
        crd/certificaterequestpolicies.policy.cert-manager.io \
        crd/certificaterequestpolicysets.policy.cert-manager.io --timeout=60s
fi

"${HELM}" upgrade upgrade-test "${UPGRADE_CHART}" \
    --namespace "${namespace}" --reuse-values --wait --timeout 180s \
    --set "image.repository=${UPGRADE_IMAGE}" \
    --set "image.tag=${UPGRADE_TAG}" --set image.pullPolicy=Never

issue_certificate after-upgrade upgrade-test
"${KUBECTL}" wait --namespace "${namespace}" --for=condition=Ready \
    certificate/after-upgrade --timeout=120s
[[ $("${KUBECTL}" get certificaterequestpolicy upgrade-standalone \
    -o jsonpath='{.spec.policySetRef}') == "" ]]

"${KUBECTL}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: upgrade-set
  namespace: ${namespace}
spec:
  selfSigned: {}
---
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicySet
metadata:
  name: upgrade-set
spec:
  selector:
    issuerRef:
      name: upgrade-set
    namespace:
      matchNames: ["${namespace}"]
  policies:
    - name: upgrade-set-allow
    - name: upgrade-set-deny
---
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: upgrade-set-deny
spec:
  policySetRef:
    name: upgrade-set
  allowed:
    commonName:
      value: deny.example.com
  selector:
    issuerRef:
      name: upgrade-set
EOF

"${KUBECTL}" wait --for=condition=Ready=false certificaterequestpolicyset/upgrade-set --timeout=60s
[[ $("${KUBECTL}" get certificaterequestpolicy upgrade-set-deny \
    -o jsonpath='{.spec.policySetRef.name}') == upgrade-set ]]
issue_certificate pending-set upgrade-set
"${KUBECTL}" wait --namespace "${namespace}" --for=create \
    certificaterequest/pending-set-1 --timeout=60s
"${KUBECTL}" wait --namespace "${namespace}" --for=create \
    event --field-selector reason=Unprocessed,involvedObject.name=pending-set-1 --timeout=60s
[[ $("${KUBECTL}" get certificaterequest pending-set-1 --namespace "${namespace}" \
    -o jsonpath='{.status.conditions[?(@.type=="Denied")].status}') != True ]]

"${KUBECTL}" apply -f - <<EOF
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: upgrade-set-allow
spec:
  policySetRef:
    name: upgrade-set
  allowed:
    commonName:
      value: "*.example.com"
    usages: ["digital signature"]
  selector:
    issuerRef:
      name: upgrade-set
EOF

"${KUBECTL}" wait --for=condition=Ready certificaterequestpolicyset/upgrade-set --timeout=60s
"${KUBECTL}" wait --namespace "${namespace}" --for=condition=Ready \
    certificate/pending-set --timeout=120s
echo "Legacy upgrade passed (Helm managed CRDs: ${MANAGE_CRDS})"
