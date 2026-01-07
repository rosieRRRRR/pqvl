# **PQVL – Post-Quantum Verification Layer**

* **Specification Version:** 1.0.3
* **Status:** Implementation Ready
* **Date:** 2026
**Author:** rosiea
**Contact:** [PQRosie@proton.me](mailto:PQRosie@proton.me)
**Licence:** Apache License 2.0 — Copyright 2026 rosiea

---

## **Summary**

PQVL provides runtime integrity evidence through deterministic attestation artefacts. It defines probe collection, baseline comparison, and drift classification (**NONE / WARNING / CRITICAL**) without granting authority. Attestation envelopes bind runtime measurements to verifiable time (Epoch Clock ticks) and sessions (exporter hashes), enabling **PQSEC** to gate operations on verified runtime state.

PQVL supports challenge-response attestation, baseline governance, supply-chain context, multi-node aggregation, optional lease optimisation, and optional model↔runtime cross-binding.

**PQVL produces evidence only. PQSEC enforces decisions.**

**Key Properties:**
Deterministic attestation | Drift classification | Runtime measurement | Baseline governance | Challenge-response binding | Evidence producer only

---

## **Non-Normative Overview — For Explanation and Orientation Only**

**This section is NOT part of the conformance surface.
It is provided for explanatory and onboarding purposes only.**

### Plain Summary

PQVL produces deterministic runtime attestation artefacts that describe measured system state. These artefacts are descriptive only and carry no authority. They are consumed by PQSEC to inform enforcement decisions but do not themselves permit, deny, or execute any operation.

### What PQVL Is / Is Not

| PQVL IS                          | PQVL IS NOT           |
| -------------------------------- | --------------------- |
| An attestation artefact producer | An enforcement engine |
| A runtime state describer        | An authority source   |
| A drift classifier               | A decision maker      |
| Deterministic and verifiable     | Heuristic or advisory |

### Canonical Flow

Runtime Probes → Deterministic Measurement → Baseline Comparison → Drift Classification → AttestationEnvelope

### Why This Exists

Systems fail when attestation is treated as permission. PQVL deliberately separates **measurement** from **authority**, allowing PQSEC to make deterministic, policy-bound decisions without collapsing trust boundaries.

---

## **1. Scope and Attestation Boundary (Normative)**

PQVL defines deterministic, cryptographically verifiable **runtime attestation artefact production only**.

PQVL normatively defines:

* attestation artefact classes
* canonical structures and encoding rules
* challenge-response binding semantics
* baseline governance artefacts
* drift classification rules
* attestation lease optimisation artefacts
* error conditions for artefact validity

**Attestation Boundary**

PQVL produces descriptive attestation artefacts only.

PQVL does **not** perform enforcement, refusal, escalation, lockout, backoff, freshness enforcement, monotonicity enforcement, or authority decisions. All operational decisions based on PQVL artefacts are defined exclusively by consuming specifications, primarily **PQSEC**.

Any implementation deriving authority or enforcement decisions directly from PQVL is non-conformant.

---

## **2. Non-Goals and Authority Boundary**

PQVL does not define:

* custody authority or custody policy
* enforcement engines or refusal semantics
* time anchoring, issuance, or profile governance
* Bitcoin execution semantics
* AI behaviour, inference, or alignment enforcement
* transport protocols or session establishment
* vendor trust or hardware guarantees

**Authority Boundary**

PQVL artefacts carry zero authority. They describe measured runtime state only. Authority and enforcement are external.

---

## **3. Threat Model**

PQVL assumes adversaries may:

* compromise runtime environments
* tamper with binaries, configuration, or boot chains
* replay stale attestation artefacts
* omit required attestation components
* attempt canonical encoding ambiguity
* attempt substitution of attestation inputs

PQVL does not assume trusted runtimes, trusted networks, trusted clocks, or trusted coordinators.

---

## **4. Trust Assumptions**

PQVL operates under the following assumptions:

* attestation claims derive only from canonical artefacts and valid signatures
* baseline definitions are external governance inputs
* time semantics are supplied externally
* encoding determinism is required for cross-implementation consistency

PQVL does not treat attestation evidence as ground truth.

---

## **5. Architecture Overview**

PQVL consists of:

* **Attestation Artefact Classes** – concrete outputs of runtime measurement
* **Challenge-Response Binding** – nonce-based freshness binding
* **Baseline Governance Layer** – expected runtime state, no enforcement
* **Lease Optimisation Layer** – optional short-lived cache artefacts

PQVL defines structure and production rules only.

---

## **6. Canonical Encoding**

### 6.1 PQVL Native Artefacts

1. All PQVL native artefacts that are hashed, signed, or compared MUST be encoded using **Deterministic CBOR**.
2. Re-encoding MUST produce byte-identical output.
3. Non-canonical encodings MUST be rejected.

### 6.2 Epoch Clock Canonical JSON Exception

1. Epoch Clock ticks MUST be referenced using the **exact JCS Canonical JSON bytes**.
2. PQVL MUST NOT re-encode Epoch Clock ticks into CBOR or any other format.
3. Any binding to time MUST bind to:

   * the Epoch Clock JSON bytes directly, or
   * a hash computed over those bytes.

## 6.3 Attestation UNAVAILABLE Semantics (Normative)

`UNAVAILABLE` indicates that PQVL cannot produce a valid runtime attestation artefact due to genuine absence of required prerequisites or operating conditions.

### 6.3.1 Meaning of UNAVAILABLE

Examples (non-exhaustive):

* early boot before probes can be collected
* probe collection in progress or incomplete
* required hardware attestation interface unavailable
* secure enclave, TPM, or TEE temporarily inaccessible

`UNAVAILABLE` does not assert validity or invalidity of runtime state. It asserts absence of evaluable evidence only.

### 6.3.2 Artefact Production Rules

1. When runtime evidence is UNAVAILABLE, PQVL MUST NOT produce an AttestationEnvelope.
2. PQVL MUST NOT emit partial, cached, stale, or heuristic artefacts to avoid UNAVAILABLE.
3. PQVL MUST surface UNAVAILABLE explicitly to consuming components.
4. PQVL MUST NOT map UNAVAILABLE to drift states (NONE, WARNING, CRITICAL).

### 6.3.3 Drift Classification Boundary

Drift classification applies only when valid attestation artefacts exist.

If runtime evidence is UNAVAILABLE:

* no drift classification MUST be produced
* no drift downgrade or escalation MUST be inferred

### 6.3.4 Enforcement Boundary

PQVL does not map UNAVAILABLE to permission, refusal, or degradation.

All enforcement decisions derived from UNAVAILABLE outcomes are performed exclusively by PQSEC according to active policy and operation class.

### 6.3.5 Determinism Requirement

Given identical runtime availability and operating conditions, PQVL MUST produce identical UNAVAILABLE outcomes.

### 6.3.6 Audit Handling

Implementations MAY record UNAVAILABLE events for local diagnostics.

Such records:

1. MUST remain local,
2. MUST NOT be treated as enforcement artefacts, and
3. MUST NOT be exported as evidence.


---

## **7. Probe Type Definitions**

PQVL MUST support the following core probe types:

### 7.1 system_state

Purpose: OS and hardware integrity
Examples: boot measurements, kernel modules, secure boot state

### 7.2 process_state

Purpose: application and process integrity
Examples: process list, loaded libraries, executable identity

### 7.3 integrity_state

Purpose: code and configuration integrity
Examples: binary hashes, config hashes, container image hash

### 7.4 policy_state

Purpose: policy and ruleset integrity
Examples: active policy identifiers, policy hashes, policy module versions

---

## **8. Attestation Artefact Classes**

### 8.1 ProbeResult

```
ProbeResult = {
  probe_type: "system_state" / "process_state" / "integrity_state" / "policy_state",
  status: "valid" / "warning" / "invalid",
  details: { * tstr => any },
  tick: uint,
  probe_id: tstr
}
```

Requirements:

1. Deterministic probe_type
2. Deterministic status
3. Canonically encoded details
4. Externally supplied EpochTick

### **8.1.1 Probe Determinism Requirements (Normative)**

Canonical measurements MUST be deterministic across identical runtime states.

Non-deterministic elements (for example timestamps, process IDs, random nonces) MUST be:

* excluded from canonical measurement fields, or
* normalised to deterministic representations, or
* placed in non-canonical operational metadata sections.

Canonical measurements are signed and hashed. Operational metadata is excluded.

Canonical fields include:

* code_hash
* config_hash
* binary_hash
* version_string (semantic only)
* module_list (sorted)
* policy_hash

Failure to produce deterministic canonical output results in:

* status = `invalid`
* drift_state = `CRITICAL`

### **8.1.2 Probe Collection Timing (Guidance)**

Probe collection SHOULD occur:

* at attestation request time (challenge-response),
* after significant state changes (if continuous attestation is used),
* before critical operations when cached artefacts are present.

Probe staleness windows and reuse policies are defined by **PQSEC**, not PQVL.

---

### 8.2 TPMQuote

```
TPMQuote = {
  pcr_values: { * uint => bstr },
  nonce: bstr,
  signature: bstr,
  suite_profile: tstr
}
```

### 8.3 TEEReport

```
TEEReport = {
  measurement: bstr,
  nonce: bstr,
  report_data: bstr,
  signature: bstr,
  suite_profile: tstr
}
```

### 8.4 MeasuredBootChain

```
MeasuredBootChain = {
  stage_hashes: [* bstr],
  nonce: bstr,
  signature: bstr,
  suite_profile: tstr
}
```

---

## **9. AttestationChallenge**

```
AttestationChallenge = {
  challenge_id: tstr,
  nonce: bstr,
  issued_tick: uint,
  expiry_tick: uint,
  session_id: tstr,
  exporter_hash: bstr
}
```

---

## **10. AttestationResponse**

```
AttestationResponse = {
  challenge_id: tstr,
  artefacts: [* TPMQuote / TEEReport / MeasuredBootChain ],
  response_tick: uint,
  exporter_hash: bstr
}
```

### **10.1 Response vs Envelope Relationship (Guidance)**

* **AttestationResponse** contains raw measurement artefacts collected in response to a challenge.
* **AttestationEnvelope** contains the classified, canonical, signed summary intended for PQSEC consumption.

Typical flow:
Challenge → Response → Classification → Envelope

---

## **11. RuntimeBaseline Governance**

```
RuntimeBaseline = {
  baseline_id: tstr,
  expected_hashes: { * tstr => bstr },
  issued_tick: uint,
  expiry_tick: uint,
  suite_profile: tstr,
  signature: bstr
}
```

RuntimeBaseline defines expectations only. Interpretation is external.

---

## **12. Baseline Updates and Rollout**

Baselines MUST be versioned, signed, lineage-tracked, and support gradual rollout and rollback.

---

## **13. Supply-Chain Attestation Integration**

### 13.1 Build Environment Probe

```
BuildEnvProbe = {
  probe_type: "build_env",
  compiler_hash: bstr,
  toolchain_hash: bstr,
  dependency_manifest_hash: bstr,
  build_flags_hash: bstr
}
```

### 13.2 Supply-Chain Context

```
supply_chain_context = {
  build_attestation_hash: bstr / null,
  runtime_signature_hash: bstr / null,
  publish_signature_hash: bstr / null
}
```

---

## **14. Drift Classification**

States:

* NONE
* WARNING
* CRITICAL

Drift is descriptive only.

---

## **15. AttestationEnvelope**

```
AttestationEnvelope = {
  envelope_id: tstr,
  artefacts: [* TPMQuote / TEEReport / MeasuredBootChain ],
  baseline_id: tstr / null,
  drift_state: "NONE" / "WARNING" / "CRITICAL",
  issued_tick: uint,
  exporter_hash: bstr,
  signature: bstr
}
```

---

## **16. Multi-Node Attestation Aggregation**

### **16.1 Aggregation Rules (Normative)**

For M-of-N attestation:

* Aggregate drift equals the most severe individual drift
  (`CRITICAL > WARNING > NONE`)
* If any node is CRITICAL → aggregate CRITICAL
* If any node is WARNING and none CRITICAL → aggregate WARNING
* All nodes NONE → aggregate NONE

If fewer than M nodes attest successfully, aggregate drift MUST be CRITICAL.

---

## **17. AttestationLease**

```
AttestationLease = {
  lease_id: tstr,
  envelope_id: tstr,
  issued_tick: uint,
  expiry_tick: uint,
  exporter_hash: bstr,
  signature: bstr
}
```

Leases convey no authority. Enforcement is external.

---

## **18. Failure Semantics**

Invalid, missing, or non-canonical artefacts MUST be rejected. PQVL defines no enforcement behaviour.

---

## **19. Error Codes**

E_RUNTIME_INVALID
E_RUNTIME_STALE
E_RUNTIME_DRIFT_CRITICAL
E_RUNTIME_DRIFT_WARNING
E_PROBE_MISSING
E_PROBE_INVALID
E_PROBE_NONCANONICAL
E_PROBE_NON_DETERMINISTIC
E_SIGNATURE_INVALID
E_TICK_INVALID
E_TICK_STALE
E_TICK_EXPIRED
E_EXPORTER_MISMATCH
E_LEASE_EXPIRED
E_BASELINE_MISMATCH

### **19.1 Error Code Semantics (Guidance)**

Error codes are descriptive only. They:

* inform PQSEC decisions,
* do not imply specific enforcement outcomes,
* do not trigger automatic actions within PQVL.

---

## **20. Conformance**

A PQVL-conformant implementation produces only defined artefacts, enforces deterministic encoding, preserves Epoch Clock JSON bytes, classifies drift deterministically, and does not enforce authority.

## 20A. Security Considerations

### Threats Addressed

* Undetected runtime compromise
* Stale attestation replay
* Attestation forgery

### Threats NOT Addressed

* Sophisticated rootkits
* Hardware-level attacks
* Enforcement bypass

### Authority Boundary

PQVL produces attestation artefacts only.
All enforcement decisions are delegated to PQSEC.

### Fail-Closed Semantics

* Invalid probes → drift_state = CRITICAL
* Non-deterministic measurements → invalid
* Signature failure → artefact rejection


## **21. Explicit Dependencies**

* **PQSF** ≥ 2.0.2
* **Epoch Clock** ≥ 2.1.1
* **PQSEC** ≥ 2.0.1

---

## **Annex E — Model ↔ Runtime Cross-Binding (Normative)**

### E.1 Scope

Defines descriptive cross-binding between runtime attestation and external model identity artefacts.

### E.2 Rules

1. Runtime attestation MAY reference HardwareBindingEvidence or model identity references.
2. Drift classification MUST remain unchanged.
3. Binding failure MUST NOT grant authority.

### E.3 Optional Extension

```
model_runtime_binding = {
  model_identity_ref: tstr / bstr,
  binding_hash: bstr / null,
  suite_profile: tstr
}
```

---

## **Annex A — Attestation Challenge Flow (Non-Normative)**

1. Challenge issued
2. Runtime measures
3. Response returned
4. AttestationEnvelope produced
5. Evaluated via PQSEC

---

## **Annex B — Example TPMQuote (Non-Normative)**

```json
{
  "pcr_values": { "0": "01ab", "7": "02cd" },
  "nonce": "aa55",
  "signature": "bb66",
  "suite_profile": "profile:tpmsig:v1"
}
```

---

## **Annex C — Reference Attestation Cycle (Non-Normative)**

```python
def pqvl_attest_runtime(env):
    probes = collect_probes(env)
    drift = classify(probes)
    tick = env.external_tick
    payload = canonicalize(probes, drift, tick)
    return sign(payload)
```

---

## **Annex D — Required Probe Check (Non-Normative)**

```python
def required_ok(probes):
    return all(p.type in probes for p in ["system_state","process_state","integrity_state"])
```

---

## **Annex F — Drift Classification (Non-Normative)**

```python
def classify(probes):
    if any(p.status=="invalid" for p in probes): return "CRITICAL"
    if any(p.status=="warning" for p in probes): return "WARNING"
    return "NONE"
```

---

## **Annex G — Error Mapping Helper (Non-Normative)**

```python
def map_error(ctx):
    if ctx.signature_invalid: return "E_SIGNATURE_INVALID"
    if ctx.probe_missing: return "E_PROBE_MISSING"
    if ctx.drift=="CRITICAL": return "E_RUNTIME_DRIFT_CRITICAL"
    return "E_RUNTIME_INVALID"
```

---

PQVL (Post-Quantum Verification Layer)
Changelog
Version 1.0.3 (Current)
Attestation Envelopes: Standardized the use of Attestation Envelopes to bind runtime measurements to verifiable Epoch Clock ticks and session exporter hashes.

Drift Classification: Adopted the ecosystem-wide NONE / WARNING / CRITICAL drift classification for runtime integrity reports.

Attestation Leases: Introduced short-lived lease artefacts to optimize performance by reducing the frequency of full attestation verification.

Authority Separation: Explicitly removed all lockout, refusal, and backoff semantics, designating PQVL as an "evidence producer only" for consumption by PQSEC.

---

## **Acknowledgements (Informative)**

This specification builds on decades of work in systems security, cryptographic engineering, and practical attestation.

The author acknowledges the foundational contributions of:

* **Satoshi Nakamoto**, for establishing a trust-minimised execution and verification model that informs explicit authority boundaries.
* **Daniel J. Bernstein**, for constant-time design principles and rigorous cryptographic engineering discipline.
* **Whitfield Diffie** and **Martin Hellman**, for public-key cryptography as the basis for verifiable statements of state.
* **Ralph Merkle**, for Merkle constructions enabling tamper-evident aggregation and auditability.
* **The NIST Post-Quantum Cryptography Project**, for standardising post-quantum primitives suitable for long-lived verification artefacts.
* **The IETF community**, for canonical encoding standards (CBOR, JCS) that enable deterministic cross-implementation verification.
* **Platform security and operating-system communities**, whose work on measured boot, TPMs, TEEs, and runtime introspection informs the probe and artefact models used here.

This specification also reflects practical lessons from real-world deployments where conflating *measurement* with *authority* caused systemic failures. PQVL intentionally separates evidence production from enforcement to preserve clear trust boundaries.

Any omissions are unintentional. The inclusion of these acknowledgements does not imply endorsement of this specification by the individuals or organisations named.

If you find this work useful and want to support it, you can do so here:
bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw
