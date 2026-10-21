# Security controls mapping

How the project covers common frameworks. Each line points to where the control lives.

## OWASP Top 10 (2021)

| Category | Controls in ShieldPipe |
|---|---|
| A01 Broken Access Control | Per-record ownership filter, 404 on foreign records, admin-only routes ([incidents.py](../app/routers/incidents.py), [deps.py](../app/deps.py)) |
| A02 Cryptographic Failures | Argon2id password hashing, pinned JWT algorithm and required claims ([security.py](../app/security.py)), HSTS |
| A03 Injection | ORM with bound parameters, escaped `LIKE`, Semgrep custom rule, ZAP SQLi rules set to FAIL |
| A04 Insecure Design | [Threat model](threat-model.md) with tests mapped to each threat |
| A05 Security Misconfiguration | Security headers middleware, docs off by default, hadolint, Trivy misconfig, OPA policies, Pod Security `restricted` |
| A06 Vulnerable and Outdated Components | Hash-locked dependencies, pip-audit, Trivy fs and image gates, Dependabot |
| A07 Identification and Authentication Failures | Login throttling per account and per IP, password policy, no user enumeration |
| A08 Software and Data Integrity Failures | Actions pinned by SHA, images by digest, cosign signature, SBOM attestation, SLSA provenance |
| A09 Security Logging and Monitoring Failures | JSON audit events for authentication, authorisation and writes, ready for a SIEM |
| A10 Server-Side Request Forgery | The API makes no outbound requests, and Kubernetes egress is denied entirely |

## NIST SSDF (SP 800-218)

| Practice | Implementation |
|---|---|
| PO.3 Implement supporting toolchains | Single pipeline in [devsecops.yml](../.github/workflows/devsecops.yml); every tool pinned |
| PO.5 Secure environments | Read-only workflow tokens, per-job permissions, no long-lived credentials (OIDC signing) |
| PS.1 Protect all forms of code | Branch protection, CODEOWNERS, secret scanning over the full history |
| PS.2 Verify software release integrity | cosign keyless signature and `cosign verify` in the release job |
| PS.3 Archive and protect each release | Image pushed by digest with SBOM and provenance attestations |
| PW.1 Design to meet security requirements | [Threat model](threat-model.md) |
| PW.4 Reuse well-secured software | Lock file with hashes, audited dependencies, minimal base image |
| PW.6 Configure the build to improve security | Multi-stage build, no pip in the runtime image, non-root user |
| PW.7 Review and analyse code | ruff, Bandit, Semgrep (custom and OWASP rules), CodeQL `security-extended` |
| PW.8 Test executable code | 44 unit and security tests, authenticated ZAP API scan, Kubernetes runtime checks |
| PW.9 Configure software to have secure settings by default | Fails to start without a strong JWT secret; OpenAPI off by default |
| RV.1 Identify and confirm vulnerabilities continuously | Weekly CodeQL and Scorecard runs, Dependabot, SARIF results in GitHub Security |

## SLSA

The release job produces **SLSA Build Level 2** provenance: the build runs on GitHub-hosted runners
and the provenance is generated and signed by the platform (`actions/attest-build-provenance`).
Reaching Level 3 would mean moving the build into a reusable workflow so the calling repository
cannot influence the provenance.

## CIS Kubernetes Benchmark and Pod Security Standards

Workload controls from the Pod Security Standards `restricted` profile are enforced twice: before
merge by the [Rego policies](../policy/kubernetes/kubernetes.rego), and at admission time by the
namespace label. The end-to-end test confirms the API server rejects a privileged pod.
