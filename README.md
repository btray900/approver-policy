<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/approver-policy"><img src="https://godoc.org/github.com/cert-manager/approver-policy?status.svg" alt="approver-policy godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/approver-policy"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/approver-policy" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
  <a href="https://github.com/cert-manager/approver-policy/actions/workflows/govulncheck.yaml"><img alt="govulncheck" src="https://github.com/cert-manager/approver-policy/actions/workflows/govulncheck.yaml/badge.svg" /></a>
</p>

# approver-policy

approver-policy is a [cert-manager](https://cert-manager.io) approver that is
responsible for [Approving or Denying
CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

approver-policy exposes the CertificateRequestPolicy resource which
administrators use to define policy over what, who, and how certificates are
signed by cert-manager.

---

Please follow the documentation at
[cert-manager.io](https://cert-manager.io/docs/usage/approver-policy/) for
installing and using approver-policy.

## Coordinated policy readiness

The optional, cluster scoped CertificateRequestPolicySet resource declares the
policies that form a complete configuration. Its `spec.selector` scopes requests
by issuer and namespace independently of whether the member policies exist.
Each policy listed in `spec.policies` must opt in by referencing the set through
`spec.policySetRef`.

Members are evaluated only when every expected policy exists, references the
set, is not being deleted, and has `Ready=True` for its current generation.
Request evaluation checks the members directly rather than relying on the
set's published Ready condition. Set status reports readiness and the reasons
blocking each member.

Requesters need RBAC `use` permission for the set and every member policy.
Membership grants no approval authority, and member issuer and namespace
selectors still apply. The example
[`docs/examples/policy-set.yaml`](docs/examples/policy-set.yaml) includes the
required ClusterRole; bind it to the users or service accounts that create
CertificateRequests.

An applicable, authorized but incomplete set leaves requests Unprocessed
unless an independently eligible policy approves them. Standalone policies
and complete sets retain the existing any policy may approve behavior.
Changes to sets, policies, namespaces, or RBAC trigger reevaluation.
Policies referencing missing sets never fall back to standalone evaluation.
Policies without `spec.policySetRef` retain their existing behavior.

## Makefile modules

This project uses [Makefile modules](https://github.com/cert-manager/makefile-modules), see the README there for more information.
A summary of the available make targets can be found by running `make help`.

## Release Process

The release process is documented in [RELEASE.md](RELEASE.md).