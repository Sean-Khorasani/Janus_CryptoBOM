# Janus CryptoBOM — Feature Gap Inventory & Implementation Plan

> Derived from `docs/competitive-analysis.md`. June 2026.
> Status: 🟢 Implemented | 🟡 Designed | 🔴 Not Started

---

## Feature Inventory (24 features from Competitive Analysis)

### Tier 1 — Immediate: Make Janus the Clear Leader

| ID | Feature | Status | Architecture |
|----|---------|--------|-------------|
| F1 | **PQC Migration Simulator (Sandbox Mode)** | 🔴 | Server: `internal/sandbox/` package; UI: `SandboxRunner.tsx` |
| F2 | **SAST/CI-CD Integrations** | 🔴 | New: `.github/workflows/janus-scan.yml`, `scripts/janus-ci.sh` |
| F3 | **Fleet Quantum-Readiness Score** | 🔴 | Server: `store.Overview` extension; UI: `ReadinessScore.tsx` |
| F4 | **Compliance Report Generator** | 🔴 | Server: `GET /api/report/compliance`; UI: download buttons |
| F5 | **Runtime Algorithm Interception** | 🔴 | Agent: `interceptor.rs` extension for real-time algorithm upgrade |
| F6 | **Hybrid Certificate Pipeline** | 🔴 | Server: `certmanager` extension; integration with EJBCA/step-ca |

### Tier 2 — Short-Term: Deepen the Moat

| ID | Feature | Status | Architecture |
|----|---------|--------|-------------|
| F7 | **Statistical Confidence Analysis** | 🔴 | Server: ML-based noise filtering for findings |
| F8 | **Cloud-Native Deployment** | 🔴 | New: `deploy/helm/`, `deploy/terraform/` |
| F9 | **PQC Lab (Free Tier Sandbox)** | 🔴 | Server: `POST /api/lab/simulate`; UI: `PQCLab.tsx` |
| F10 | **Crypto Health SLA Dashboard** | 🔴 | Server: `store.SLAMetrics`; UI: `SLADashboard.tsx` |
| F11 | **Third-Party Advisory Integration** | 🔴 | Server: NVD/GHSA/vendor bulletin feed ingestion |
| F12 | **Agent Auto-Upgrade** | 🔴 | Server: binary distribution endpoint; Agent: self-update logic |

### Tier 3 — Medium-Term: Expand the Platform

| ID | Feature | Status | Architecture |
|----|---------|--------|-------------|
| F13 | **HSM Integration Layer** | 🔴 | Server: `internal/hsm/` PKCS#11 connector |
| F14 | **Mainframe Agent (z/OS)** | 🔴 | Agent: `agent-zos/` cross-compiled s390x binary |
| F15 | **Container/K8s Operator** | 🔴 | New: `deploy/operator/` Kubernetes operator |
| F16 | **Side-Channel Detection** | 🔴 | Agent: timing side-channel test harness |
| F17 | **PQC VPN/IKEv2 Integration** | 🔴 | Agent: IKEv2/IPsec PQC cipher suite injection |
| F18 | **CCoE Toolkit** | 🔴 | New: `docs/ccoe/` templates + dashboards |

### Tier 4 — Long-Term: Visionary

| ID | Feature | Status | Architecture |
|----|---------|--------|-------------|
| F19 | **Formal Verification Integration** | 🔴 | Server: Verifpal/ProVerif model generator |
| F20 | **PQC Performance Benchmarks** | 🔴 | Agent: per-machine benchmark suite |
| F21 | **ZK Proof Discovery** | 🔴 | Agent: ZKP circuit/framework detection patterns |
| F22 | **Cross-Org Risk Exchange** | 🔴 | Server: anonymous aggregation API |
| F23 | **Homomorphic Encryption Readiness** | 🔴 | Agent: FHE library detection |
| F24 | **QKD Integration** | 🔴 | Server: ETSI QKD API connector |

---

## Additional Features from Code Review

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| F25 | **Prometheus Metrics Expansion** | 🔴 | Per-asset finding counts, migration duration, webhook latency |
| F26 | **Rate Limiting on API** | 🔴 | Per-endpoint rate limiting middleware |
| F27 | **Audit Log Export** | 🔴 | CSV/JSON export of audit logs with date range filter |
| F28 | **Finding Confidence Threshold** | 🔴 | Configurable min confidence per policy profile |
| F29 | **Multi-Tenant Fleet Isolation** | 🔴 | Fleet partitioning for MSP/MSSP deployments |
| F30 | **Dark Mode Completeness** | 🟡 | Remaining components need dark: variants |
| F31 | **i18n/Localization Support** | 🔴 | React i18next integration for dashboard |
| F32 | **Accessibility (a11y)** | 🔴 | WCAG 2.1 AA compliance for dashboard |

---

## Implementation Plan

### Batch 1: Server + UI (Go compiles, can verify)
1. **F3** — Fleet Quantum-Readiness Score
2. **F4** — Compliance Report Generator
3. **F9** — PQC Lab Sandbox endpoint
4. **F10** — Crypto Health SLA metrics
5. **F12** — Agent auto-upgrade endpoint
6. **F25** — Expanded Prometheus metrics
7. **F26** — Rate limiting middleware
8. **F28** — Configurable confidence thresholds

### Batch 2: CI/CD + Infrastructure
9. **F2** — GitHub Action + CI scripts
10. **F8** — Helm chart + Terraform
11. **F27** — Audit log export

### Batch 3: Agent (Rust, verify on build)
12. **F5** — Runtime algorithm interception enhancement
13. **F16** — Side-channel detection patterns
14. **F20** — PQC performance benchmarks
15. **F23** — FHE library detection

### Batch 4: Test Suite
16. Comprehensive test plan + test data + test scripts in `.\Test\`
