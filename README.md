# **PQVL — Post-Quantum Verification Layer**

An Open Standard for Runtime Integrity Verification

**Specification Version:** v1.0.0
**Status:** Implementation Ready. Validation Test Required.
**Author:** rosiea
**Contact:** [PQRosie@proton.me](mailto:PQRosie@proton.me)
**Date:** November 2025
**Licence:** Apache License 2.0 — Copyright 2025 rosiea

-----

### **SUMMARY**

The **Post-Quantum Verification Layer (PQVL)** establishes a deterministic, cryptographically enforced standard for runtime integrity verification, serving as the foundational trust anchor for the post-quantum era. It replaces opaque, trust-based assumptions about execution environments with transparent, verification-based artifacts that are reproducible across any device, operating system, or deployment model.

PQVL cryptographically attests that a runtime is safe for high-risk operations only when all core predicates evaluate to true:
- **`valid_signature`** — Valid ML-DSA-65 signature
- **`valid_tick`** — Fresh, monotonic Epoch Clock tick
- **`valid_freshness`** — Tick within stipulated window (≤900 seconds)
- **`valid_required_probes`** — All mandatory probes present and canonical
- **`(drift_state == "NONE")`** — No integrity drift detected

**Core Components:**
1. **Canonical Probes** — Four required probe classes (`system_state`, `process_state`, `integrity_state`, `policy_state`) with deterministic measurement
2. **AttestationEnvelope** — Signed aggregate of probe results with drift classification and tick binding
3. **Drift Classification** — Deterministic rules for NONE/WARNING/CRITICAL states with fail-closed enforcement
4. **Tick Freshness** — Epoch Clock binding for replay protection and temporal validity
5. **Ecosystem Integration** — Authoritative runtime predicates for PQSF (`valid_runtime`), PQHD (`valid_device`), and PQAI (`valid_runtime`)
6. **Transport & Ledger** — Secure transport (TLSE-EMP/STP) with canonical ledger events for auditability

PQVL enables wallets, AI systems, and policy engines to operate exclusively under verified safe runtime conditions, making tampering, misconfiguration, and state drift detectable and cryptographically enforced.

---

# **INDEX**

### **[ABSTRACT](#abstract)**

### **[PROBLEM STATEMENT](#problem-statement)**

---

## **1. PURPOSE AND SCOPE (NORMATIVE)**

* [1.1 Purpose](#11-purpose)
* [1.1A Trust-Minimisation (INFORMATIVE)](#11a-trust-minimisation-informative)
* [1.2 Scope](#12-scope)
* [1.3 Relationship to PQSF](#13-relationship-to-pqsf)
* [1.4 Relationship to PQHD](#14-relationship-to-pqhd)
* [1.5 Relationship to PQAI](#15-relationship-to-pqai)
* [1.6 Relationship to Epoch Clock](#16-relationship-to-epoch-clock)

---

## **2. ARCHITECTURE OVERVIEW (NORMATIVE)**

* [2.1 Components](#21-components)
* [2.2 Data Flow Overview](#22-data-flow-overview)
* [2.3 Trust Model](#23-trust-model)
* [2.3.1 Offline and Sovereign Operation](#231-offline-and-sovereign-operation)
* [2.4 Device Identity Models (NORMATIVE)](#24-device-identity-models-normative)

  * [2.4.1 Attested Device Identity](#241-attested-device-identity)
  * [2.4.2 Minimal Device Identity](#242-minimal-device-identity-no-pqvl-present)
  * [2.4.3 Identity Selection Rules](#243-identity-selection-rules)

---

## **3. CRYPTOGRAPHIC PRIMITIVES (NORMATIVE)**

* [3.1 Signature Requirements (ML-DSA-65)](#31-signature-requirements)
* [3.2 Hash Functions (SHAKE256-256)](#32-hash-functions)
* [3.3 Domain Separation](#33-domain-separation)
* [3.4 Canonical Encoding](#34-canonical-encoding)

---

## **4. ATTESTATION MODEL & PROBE STRUCTURES (NORMATIVE)**

* [4.1 Probe Types](#41-probe-types)
* [4.2 ProbeResult Structure](#42-proberesult-structure)
* [4.3 AttestationEnvelope Structure](#43-attestationenvelope-structure)
* [4.4 Attestation Validation Rules](#44-attestation-validation-rules)
* [4.5 Required Probes per Enforcement](#45-required-probes-per-enforcement)

---

## **5. DRIFT CLASSIFICATION & SEMANTICS (NORMATIVE)**

* [5.1 Drift States](#51-drift-states)
* [5.2 Drift Predicate](#52-drift-predicate)
* [5.3 Impact on Consumers](#53-impact-on-consumers)
* [5.4 Required Probe Baseline Comparison](#54-required-probe-baseline-comparison)
* [5.5 Drift MUST Fail-Closed](#55-drift-must-fail-closed)

---

## **6. PQSF INTEGRATION (NORMATIVE)**

* [6.1 Probe API Integration](#61-probe-api-integration)
* [6.2 Tick Validation](#62-tick-validation)
* [6.3 Exporter Binding](#63-exporter-binding)
* [6.4 Ledger Integration](#64-ledger-integration)
* [6.5 Fail-Closed Enforcement](#65-fail-closed-enforcement)

---

## **7. PQHD INTEGRATION (NORMATIVE)**

* [7.1 Required Condition](#71-required-condition)
* [7.2 Continuous Predicate-Scoped Checks](#72-continuous-predicate-scoped-checks)
* [7.3 Impact on Recovery & Secure Import](#73-impact-on-recovery--secure-import)
* [7.4 Canonical PQVL Handling](#74-canonical-pqvl-handling)

---

## **8. PQAI INTEGRATION (NORMATIVE)**

* [8.1 Required Condition](#81-required-condition)
* [8.2 PQVL Enforcement During Fingerprinting](#82-pqvl-enforcement-during-fingerprinting)
* [8.3 PQVL Enforcement During Safe-Prompt Flows](#83-pqvl-enforcement-during-safe-prompt-flows)
* [8.4 PQAI Probe API Integration](#84-pqai-probe-api-integration)

---

## **9. TRANSPORT REQUIREMENTS (NORMATIVE)**

* [9.1 Deterministic Transport (TLSE-EMP / STP)](#91-deterministic-transport)
* [9.2 Offline Operation](#92-offline-operation)
* [9.3 Stealth Mode](#93-stealth-mode)

---

## **10. CANONICALISATION RULES (NORMATIVE)**

* [10.1 Canonical AttestationEncoding](#101-canonical-attestationencoding)
* [10.2 Probe Canonicalisation](#102-probe-canonicalisation)
* [10.3 Baseline Hash Canonicalisation](#103-baseline-hash-canonicalisation)

---

## **11. ERROR CODES (NORMATIVE)**

---

## **12. SECURITY CONSIDERATIONS (INFORMATIVE)**

---

## **13. IMPLEMENTATION NOTES (INFORMATIVE)**

---

## **14. BACKWARDS COMPATIBILITY (INFORMATIVE)**

---

### **ANNEXES**

#### **[ANNEX A — Probe Examples](https://github.com/rosieRRRRR/pqvl/blob/main/docs/probe-examples.md)**

#### **[ANNEX B — Attestation & Drift Examples](https://github.com/rosieRRRRR/pqvl/blob/main/docs/attestation-examples.md)**

#### **[ANNEX C — Developer Workflow Examples](https://github.com/rosieRRRRR/pqvl/blob/main/docs/developer-workflows.md)**

# **[ACKNOWLEDGEMENTS (INFORMATIVE)](#acknowledgements-informative)**

---

# **ABSTRACT**

The Post-Quantum Verification Layer (PQVL) establishes the foundational trust anchor for the post-quantum computing era, providing the first open, deterministic standard for runtime integrity verification.

Unlike proprietary hardware enclaves or cloud-dependent attestation services, PQVL democratizes trust by enabling any system, from wallets to AI models, to cryptographically prove its execution environment is uncompromised without external services, vendor lock-in, or specialized hardware. PQVL defines a canonical framework for measuring, encoding, and signing runtime state, producing verifiable attestations that are reproducible across platforms and deployments.

As the mandatory root of trust for the broader PQ* stack, including PQHD wallets and PQAI alignment systems, PQVL enforces a strict fail-closed security model. No high-risk operation proceeds under a compromised or unverified runtime. Its attestation envelopes, post-quantum ML-DSA-65 signatures, tick-bound freshness, and deterministic drift classification create a universal basis for trust that functions identically in online, offline, air-gapped, and fully sovereign environments.

PQVL is not an incremental improvement but an architectural shift that replaces opaque and centralized trust mechanisms with a transparent, user-controlled, and universally verifiable standard for runtime integrity.

---

# **PROBLEM STATEMENT**

Runtime environments are frequently assumed to be trustworthy by default. Existing approaches for environment integrity rely on ad-hoc tooling, vendor-specific attestation services, cloud-based trust mechanisms, or unverifiable heuristics. These methods are inconsistent, often opaque, and cannot be reliably reproduced or audited across deployments. There is no widely adopted, deterministic standard for representing runtime state, validating integrity, or detecting meaningful drift in execution conditions.

Security-sensitive systems—whether cryptographic wallets, policy engines, or AI alignment frameworks—require a consistent and verifiable method for determining whether runtime conditions can be trusted. Without such a method, higher-level systems must either trust the environment blindly or implement bespoke checks that cannot guarantee reproducibility or cross-implementation safety.

PQVL addresses these gaps by defining canonical probe types, deterministic attestation envelopes, post-quantum signatures, tick-bound freshness semantics, and a uniform drift-classification model. This enables runtime integrity to be evaluated using explicit, reproducible, and fully local verification rules without relying on cloud services, vendor enclaves, or proprietary attestation mechanisms.

---

# **1. PURPOSE AND SCOPE (NORMATIVE)**

## **1.1 Purpose**

PQVL establishes a deterministic, OS-agnostic framework for:

* measuring runtime configuration and state through canonical probes;
* aggregating these probe results into a signed AttestationEnvelope;
* classifying runtime drift (NONE, WARNING, CRITICAL) using reproducible baseline comparisons;
* binding runtime validity to Epoch Clock ticks for freshness and replay resistance;
* exposing verified runtime state to PQSF, PQHD, PQAI, and other consuming systems.

The purpose of PQVL is to provide a cryptographically verifiable, reproducible, and deployment-independent method for determining whether an execution environment is safe to trust.

### Pseudocode (Informative) — High-Level PQVL Attestation Cycle

```
// High-level PQVL attestation cycle for one device
function pqvl_attest_runtime(env):
    // 1. Collect probes from OS / tools
    probes = []
    probes.append(run_system_state_probe(env))
    probes.append(run_process_state_probe(env))
    probes.append(run_integrity_state_probe(env))
    if env.has_policy_engine:
        probes.append(run_policy_state_probe(env))

    // 2. Canonicalise each ProbeResult
    canonical_probes = []
    for p in probes:
        canonical_probes.append(canonical_encode(p))

    // 3. Classify drift from probe statuses and baselines
    drift_state = pqvl_classify_drift(probes, env.baselines)

    // 4. Fetch current Epoch Tick from PQSF / Epoch Clock
    tick = PQSF.get_current_tick()

    // 5. Build AttestationEnvelope (without signature)
    envelope = {
        "envelope_id": null, // placeholder
        "probes":      probes,
        "drift_state": drift_state,
        "tick":        tick
    }

    // 6. Compute envelope_id over canonical form without signature
    tmp = clone(envelope)
    tmp.signature_pq = null
    canonical_bytes = canonical_encode(tmp)
    envelope.envelope_id = shake256_256(canonical_bytes)

    // 7. Sign AttestationEnvelope with ML-DSA-65
    sig_bytes = sign_pq(env.attestation_sk, canonical_bytes)
    envelope.signature_pq = sig_bytes

    // 8. Return to PQSF / consumers
    return envelope
```

## **1.2 Scope**

PQVL defines:

* canonical probe types and their status semantics;
* deterministic ProbeResult and AttestationEnvelope structures;
* hashing and signature requirements for attestation artefacts;
* tick-bounded freshness, monotonicity enforcement, and rollback detection;
* drift classification rules and their implications for consuming systems;
* integration with PQSF’s Probe API, transport, and ledger;
* rules for evaluating `valid_device` (PQHD) and `valid_runtime` (PQAI);
* offline, sovereign, and air-gapped operation requirements.

PQVL does **not** define:

* OS internals or kernel APIs;
* hardware-specific measurement mechanisms;
* TPM/TEE attestation protocols (though it MAY consume them);
* vendor-specific integrity measurement tools;
* application-level business logic.

PQVL specifies **what** must be represented and **how** it must be validated, without constraining the underlying measurement mechanisms used to generate probe data.

---

## **1.1A Trust-Minimisation (Informative)**

PQVL operates under a strict trust-minimisation model. It does not assume trust in the operating system, hardware vendor, firmware, cloud infrastructure, or external attestation authorities. All runtime-integrity claims derive from explicit, deterministic probes and post-quantum signatures. Expected baselines, policy definitions, and probe configurations may be audited, forked, or replaced without dependency on proprietary mechanisms or centralised control.

PQVL MUST function in offline, air-gapped, and sovereign environments. Attestation generation, drift classification, and envelope validation MUST remain fully operational without remote services, cloud APIs, or vendor-managed trust modules. Verification is local, deterministic, and reproducible across devices, allowing runtime integrity to remain verifiable even in adversarial or disconnected conditions.

---

# **WHAT THIS SPECIFICATION COVERS**

This specification defines:

1. **Probe Types and Semantics**
   Canonical definitions for `system_state`, `process_state`, `policy_state`, and `integrity_state`, including required fields and status semantics.

2. **ProbeResult Structure**
   Deterministic CBOR/JCS JSON encoding, tick binding, and hash semantics for individual measurements.

3. **AttestationEnvelope**
   A canonical, ML-DSA-65-signed aggregate of ProbeResults containing runtime drift_state, envelope identifiers, and Epoch Tick binding.

4. **Drift Classification Model**
   Deterministic classification rules for NONE, WARNING, and CRITICAL drift states based on baseline matching and probe validity.

5. **Tick and Freshness Rules**
   Epoch Clock tick integration, freshness windows, rollback detection, and monotonicity enforcement.

6. **Runtime-Validity Interface for Consumers**
   How PQSF, PQHD, PQAI, and other systems interpret PQVL’s output to determine `valid_runtime` or `valid_device`.

7. **Deterministic Transport Requirements**
   TLSE-EMP or STP transport rules for attestation delivery, exporter binding, and replay resistance.

8. **Ledger Integration**
   Required ledger events for runtime_attested, drift_warning, drift_critical, and probe summaries within PQSF-compliant ledgers.

9. **Device Identity Models**
   Canonical attested and minimal device-identity structures and precedence rules for selection.

10. **Error Codes**
    A structured set of runtime-integrity, tick-freshness, canonicalisation, signature, and exporter-mismatch errors.

Informative annexes provide examples, workflows, and reference patterns for probe execution, drift handling, baseline definition, and attestation lifecycles without modifying the normative requirements above.

---

## **1.3 Relationship to PQSF**

PQSF defines the transport, temporal, encoding, and ledger rules that PQVL attestations must follow. PQVL MUST integrate with PQSF as follows:

* **EpochTick** — all AttestationEnvelopes MUST include a valid, fresh tick and MUST reject stale or rollback ticks (see PQSF 4).
* **Deterministic encoding** — PQVL MUST encode ProbeResult and AttestationEnvelope objects using PQSF canonical encoding rules (see PQSF 3.5).
* **Transport binding** — AttestationEnvelopes MUST be carried over PQSF transports (TLSE-EMP or STP) and MUST bind to the exporter_hash when present (see PQSF 7).
* **Probe API** — PQVL MUST expose runtime.attestation probes via the PQSF Probe API for consumption by PQHD, PQAI, and other modules (see PQSF 6.3).
* **Ledger integration** — PQVL MUST commit runtime_attested and drift events to the PQSF ledger for auditability and cross-device reconciliation (see PQSF 8).
* **Fail-closed semantics** — PQSF MUST treat PQVL drift_state = CRITICAL, invalid attestation, stale tick, or canonicalisation failure as immediate fail-closed conditions (see PQSF 12.3).

PQVL supplies the runtime-validity predicate used across the PQ ecosystem but does not modify PQSF primitives.

### Pseudocode (Informative) — PQSF Consuming PQVL

```
// PQSF helper to evaluate runtime validity from a PQVL AttestationEnvelope
function pqsf_evaluate_runtime(attestation, current_tick, window):
    if not pqvl_validate_envelope(attestation, current_tick, window):
        return { valid_runtime: false, error: "E_RUNTIME_INVALID" }

    if attestation.drift_state == "CRITICAL":
        return { valid_runtime: false, error: "E_RUNTIME_DRIFT_CRITICAL" }

    if attestation.drift_state == "WARNING":
        // Valid, but consumer MUST restrict high-risk activity
        return { valid_runtime: true, warning: true }

    return { valid_runtime: true, warning: false }
```

## **1.4 Relationship to PQHD**

PQHD uses PQVL to implement the `valid_device` predicate:

valid_device = (PQVL.drift_state == "NONE")

PQHD MUST:

* request PQVL attestation before signing
* treat any PQVL drift CRITICAL as `valid_device = false`
* block all signatures if PQVL attestation fails or expires

PQVL does not know anything about PSBTs, keys, or wallet policies; it reports runtime integrity only (see PQHD 12).

### Pseudocode (Informative) — PQHD Device Predicate

```
// PQHD device validity predicate using PQVL
function pqhd_valid_device(attestation, current_tick, window):
    if not pqvl_validate_envelope(attestation, current_tick, window):
        return false

    return (attestation.drift_state == "NONE")
```

## **1.5 Relationship to PQAI**

PQAI uses PQVL to implement the `valid_runtime` predicate:

* fingerprint evaluation
* ModelProfile checking
* behavioural self-introspection
* prompt-level safety checks
* model-mediated PQHD actions

If PQVL indicates integrity failure or drift, PQAI MUST fail-closed. PQVL is the authoritative runtime-integrity layer for PQAI (see PQAI 1.5).

### Pseudocode (Informative) — PQAI Runtime Check

```
// PQAI mapping of PQVL to valid_runtime
function pqai_valid_runtime(attestation, current_tick, window):
    if not pqvl_validate_envelope(attestation, current_tick, window):
        return false

    return (attestation.drift_state == "NONE")
```

## **1.6 Relationship to Epoch Clock**

PQVL MUST bind all attestation results to Epoch Clock ticks:

* every AttestationEnvelope MUST include a tick,
* attestation freshness MUST be measured in ticks, not local time,
* rollbacks and stale state MUST be detectable as tick violations.

### Pseudocode (Informative) — Tick Freshness for Attestation

```
// Validate that an attestation tick is fresh relative to current_tick
function pqvl_tick_fresh(attestation_tick, current_tick, window):
    return (attestation_tick >= current_tick - window)
```

---

# **2. ARCHITECTURE OVERVIEW (NORMATIVE)**

PQVL is an overlay verification layer that runs on top of existing operating systems and hardware. It does not require modifications to the OS or firmware; it standardises how runtime integrity is *represented*, *verified*, and *consumed*.

## **2.1 Components**

PQVL consists of:

1. **Probe Engine**

   * Collects low-level runtime signals (from OS, security modules, external tools).
   * Produces canonical `ProbeResult` objects.

2. **Attestation Engine**

   * Aggregates ProbeResult objects into an `AttestationEnvelope`.
   * Signs envelopes with ML-DSA-65.

3. **Drift Classifier**

   * Compares current probes against expected baselines (hashes, policy).
   * Produces `drift_state` = NONE, WARNING, CRITICAL.

4. **Tick Binding Layer**

   * Attaches Epoch Tick to every attestation.
   * Enforces attestation freshness.

5. **Integration Layer**

   * Exposes results to PQSF, PQHD, PQAI via Probe API and local interfaces.

### Pseudocode (Informative) — Component-Level Flow

```
// Orchestrated architecture flow
function pqvl_run_cycle(env):
    // Probe Engine
    probes = collect_all_required_probes(env)

    // Drift Classifier
    drift_state = pqvl_classify_drift(probes, env.baselines)

    // Tick Binding Layer
    tick = PQSF.get_current_tick()

    // Attestation Engine
    envelope = build_attestation_envelope(probes, drift_state, tick, env.attestation_sk)

    // Integration Layer
    PQSF.register_probe("runtime.verification", envelope)
    PQSF.ledger_append_runtime_event(envelope)

    return envelope
```

## **2.2 Data Flow Overview**

1. Probes are executed against the runtime.
2. Probe results are canonicalised.
3. Drift classifier compares results with expected baselines.
4. AttestationEnvelope is constructed and signed.
5. Epoch Tick is attached.
6. Envelope is returned to PQSF/PQHD/PQAI.
7. Ledger is updated with attestation event and drift state.

## **2.3 Trust Model**

PQVL assumes:

* the OS and tooling can provide signals that are at least locally meaningful;
* the ML-DSA-65 signing key used by PQVL is stored securely (e.g., in a signer or secure module);
* Epoch Clock ticks are valid and monotonic;
* PQSF will enforce fail-closed behaviour on PQVL errors.

PQVL does **not** assume:

* any specific OS vendor;
* any specific kernel attestation API;
* hardware-based TPM/TEE existence (though it can consume them if present);
* network connectivity (works offline).

## 2.3.1 Offline and Sovereign Operation

PQVL MUST NOT rely on remote servers or proprietary verification endpoints.
Attestation and drift classification MUST function in offline, air-gapped, and
sovereign network environments. This ensures that runtime integrity can be
verified without external trust dependencies and preserves user control across
all deployment conditions.

## **2.4 Device Identity Models (NORMATIVE)**

PQVL defines two device identity models for use by PQSF, PQHD, PQAI, and other
consumers:

1. **Attested Device Identity** — when PQVL attestation is available.
2. **Minimal Device Identity** — when PQVL is not present or attestation is
   unavailable (e.g., bootstrap, offline, air-gapped, or constrained devices).

Both identity models MUST be canonical, deterministic, and stable across
sessions for a given device.

### **2.4.1 Attested Device Identity**

When PQVL attestation is available, the authoritative device identity MUST be
derived from the attestation public key and the measured runtime state.

```
DeviceIdentity_PQVL = {
  device_attest_pub: bstr, ; ML-DSA-65 attestation public key
  measurement_hash:  bstr, ; SHAKE256-256(firmware + runtime state)
  sandbox_hash:      bstr, ; SHAKE256-256(sandbox / policy state)
  device_label:      tstr / null
}
```

Requirements:

* MUST be encoded using deterministic CBOR or JCS JSON.
* `measurement_hash` and `sandbox_hash` MUST be computed over canonical
  representations of measured state.
* `device_attest_pub` MUST correspond to the key used to sign
  AttestationEnvelopes.
* Identity MUST remain stable while the firmware and runtime configuration
  remain unchanged.

### Pseudocode (Informative) — Building Attested Device Identity

```
// Construct DeviceIdentity_PQVL from measurement artefacts
function pqvl_build_device_identity_pqvl(attest_pub, firmware_state, sandbox_state):
    measurement_hash = shake256_256(canonical_encode(firmware_state))
    sandbox_hash     = shake256_256(canonical_encode(sandbox_state))

    identity = {
        device_attest_pub: attest_pub,
        measurement_hash:  measurement_hash,
        sandbox_hash:      sandbox_hash,
        device_label:      null
    }

    return identity
```

### **2.4.2 Minimal Device Identity (No PQVL Present)**

If PQVL cannot provide attestation, a deterministic fallback identity MAY be
used.

```
DeviceIdentity_Minimal = {
  device_pub:         bstr, ; device-bound PQHD key
  device_fingerprint: bstr, ; SHAKE256-256(device_pub)
  device_label:       tstr / null
}
```

Requirements:

* `device_pub` MUST be derived deterministically (e.g., PQHD-DF with
  `class_id = "device"`).
* MUST NOT depend on system clocks, random identifiers, or vendor serial
  numbers.
* MUST remain stable unless re-provisioned or rotated by governance.

Minimal Device Identity is unauthenticated but MAY be used for multisig role
assignment, ledger tracking, and delegated authority in non-attested
deployments.

### Pseudocode (Informative) — Minimal Device Identity

```
// Construct DeviceIdentity_Minimal from a deterministic device_pub
function pqvl_build_device_identity_minimal(device_pub):
    fingerprint = shake256_256(device_pub)
    return {
        device_pub:         device_pub,
        device_fingerprint: fingerprint,
        device_label:       null
    }
```

## **2.4.3 Identity Selection Rules**

Consumers MUST apply the following precedence:

1. If a valid PQVL AttestationEnvelope is available and drift_state = "NONE",
DeviceIdentity_PQVL MUST be used.
2. If PQVL attestation is unavailable, DeviceIdentity_Minimal MAY be used.
3. If no valid identity can be established, the device MUST be treated as
untrusted and MUST NOT perform high-risk operations.

Device identity provides a stable surface for PQHD, PQAI, and other modules to
bind roles, enforce policies, and attribute ledger events.

### **Pseudocode (Informative) — Identity Selection**
```
// Choose device identity based on PQVL availability
function select_device_identity(attestation, pqvl_identity, minimal_identity, current_tick, window):
    if pqvl_validate_envelope(attestation, current_tick, window) and
       attestation.drift_state == "NONE":
        return pqvl_identity  // DeviceIdentity_PQVL

    if minimal_identity is not null:
        return minimal_identity  // DeviceIdentity_Minimal

    return null  // device untrusted
```

---

# **3. CRYPTOGRAPHIC PRIMITIVES (NORMATIVE)**

## **3.1 Signature Requirements**

PQVL MUST use ML-DSA-65 (the NIST-standardised Dilithium Level-3 parameter set) for all AttestationEnvelope signatures. Implementations MUST use this exact parameter configuration and MUST NOT substitute alternate Dilithium variants or parameter levels.

AttestationEnvelopes MUST be signed over their canonical encoding with the signature_pq field removed. Verification MUST reconstruct the same canonical payload and validate the ML-DSA-65 signature against the attestation public key.

Classical signatures MAY be present for transitional interoperability, but PQSF, PQHD, and PQAI MUST treat the ML-DSA-65 signature as authoritative. A valid ML-DSA-65 signature MUST be interpreted as a binding assertion originating from the device associated with the attestation public key.

### **3.1.1 Pseudocode (Informative) — Signing and Verifying Envelopes**

```
// Sign canonical AttestationEnvelope payload with ML-DSA-65
function pqvl_sign_envelope(sk_pq, envelope_without_sig):
    bytes = canonical_encode(envelope_without_sig)
    signature = sign_pq(sk_pq, bytes)

    envelope = envelope_without_sig
    envelope.signature_pq = signature
    return envelope


// Verify ML-DSA-65 signature on a canonical AttestationEnvelope
function pqvl_verify_envelope_signature(pk_pq, envelope):
    tmp = clone(envelope)
    signature = tmp.signature_pq
    tmp.signature_pq = null

    bytes = canonical_encode(tmp)
    return verify_pq(pk_pq, bytes, signature)
```


## **3.2 Hash Functions**

PQVL MUST use:

* **SHAKE256-256** for hashing:

  * ProbeResult payloads,
  * attested configuration hashes,
  * expected baseline hashes,
  * AttestationEnvelope IDs.

### Pseudocode (Informative) — Envelope ID Calculation

```
// Compute envelope_id as SHAKE256-256 over canonical envelope (no signature)
function pqvl_compute_envelope_id(envelope_without_sig):
    bytes = canonical_encode(envelope_without_sig)
    return shake256_256(bytes)
```

## **3.3 Domain Separation**

PQVL MUST use explicit domain strings:

* `"PQVL-Probe"` for individual probes.
* `"PQVL-Attestation"` for AttestationEnvelope hashes.

### Pseudocode (Informative) — Domain-Separated Hash

```
// Domain-separated hash helper
function pqvl_hash_with_domain(domain, payload_bytes):
    domain_bytes = utf8_encode(domain)
    return shake256_256(concat(domain_bytes, payload_bytes))
```

## **3.4 Canonical Encoding**

All PQVL structures MUST be encoded as:

* deterministic CBOR, or
* JCS JSON,

as defined in PQSF.

Non-canonical encodings MUST be rejected.

### Pseudocode (Informative) — Canonical Encoding Strategy

```
// Global encoding mode config
const PQVL_ENCODING_MODE = "JCS_JSON"  // or "CBOR"

function canonical_encode(obj):
    if PQVL_ENCODING_MODE == "JCS_JSON":
        return jcs_canonical_json_encode(obj)
    else:
        return deterministic_cbor_encode(obj)
```

---

# **4. ATTESTATION MODEL & PROBE STRUCTURES (NORMATIVE)**

## **4.1 Probe Types**

PQVL MUST support, at minimum, the following probe types:

* `system_state` — OS-level configuration and patch state.
* `process_state` — process list, signer process identity, sandbox context.
* `policy_state` — local security policies and enforcement mode.
* `integrity_state` — hashes of critical binaries, configuration, and runtime modules.

Implementations MAY define additional probe types, but these four form the normative core.

### Pseudocode (Informative) — Running Core Probes

```
// Collect all required core probes
function collect_all_required_probes(env):
    return [
        run_system_state_probe(env),
        run_process_state_probe(env),
        run_integrity_state_probe(env),
        run_policy_state_probe_if_available(env)
    ]
```

## **4.2 ProbeResult Structure**

Each probe MUST be represented as:

```
ProbeResult = {
  "probe_type": tstr,    // e.g., "system_state"
  "status":     tstr,    // "valid" | "invalid" | "warning"
  "details":    { * tstr => any },
  "tick":       uint
}
```

* `status` describes whether the measured state matches expectations.
* `details` MAY include structured information (e.g., counts, lists of missing patches).

ProbeResult MUST be canonicalised before hashing or inclusion in AttestationEnvelope.

### Pseudocode (Informative) — Constructing a ProbeResult

```
// Example of building a system_state ProbeResult
function run_system_state_probe(env):
    details = {
        kernel_version:          env.os.kernel_version,
        security_patches_missing: env.os.missing_patch_count,
        selinux_mode:            env.os.selinux_mode
    }

    status = "valid"
    if env.os.missing_patch_count > 0:
        status = "warning"
    if env.os.compromised_flag:
        status = "invalid"

    return {
        probe_type: "system_state",
        status:     status,
        details:    details,
        tick:       PQSF.get_current_tick()
    }
```

## **4.3 AttestationEnvelope Structure**

PQVL MUST aggregate ProbeResults into an AttestationEnvelope:

AttestationEnvelope = {
  "envelope_id":    bstr,
  "probes":         [* ProbeResult],
  "drift_state":    tstr,   ; "NONE" | "WARNING" | "CRITICAL"
  "tick":           uint,
  "signature_pq":   bstr
}

`envelope_id` SHOULD be computed as:

    SHAKE256-256(canonical(envelope_without_signature))

where `envelope_without_signature` is the AttestationEnvelope object with the
`signature_pq` field removed.

`drift_state` MUST be computed according to §5.

### **Pseudocode (Informative) — Building an AttestationEnvelope**

```
// Build an AttestationEnvelope from probes and drift_state
function build_attestation_envelope(probes, drift_state, tick, sk_pq):
    envelope = {
        envelope_id:  null,
        probes:       probes,
        drift_state:  drift_state,
        tick:         tick,
        signature_pq: null
    }

    tmp = clone(envelope)
    tmp.signature_pq = null

    bytes = canonical_encode(tmp)

    envelope.envelope_id = pqvl_hash_with_domain("PQVL-Attestation", bytes)
    envelope.signature_pq = sign_pq(sk_pq, bytes)

    return envelope
```

## **4.4 Attestation Validation Rules**

A PQSF/PQHD/PQAI consumer MUST reject an AttestationEnvelope if:

* signature_pq invalid,
* tick stale beyond configured window,
* canonical encoding invalid,
* any required probe is missing,
* envelope_id mismatch (if used),
* drift_state = CRITICAL (for high-risk flows).

### Pseudocode (Informative) — Envelope Validation

```
// Validate AttestationEnvelope against PQVL rules
function pqvl_validate_envelope(envelope, current_tick, window):
    // 1. Signature
    if not pqvl_verify_envelope_signature(get_attest_pub_for_envelope(envelope), envelope):
        return false

    // 2. Tick freshness
    if not pqvl_tick_fresh(envelope.tick, current_tick, window):
        return false

    // 3. Required probes present
    if not pqvl_has_required_probes(envelope.probes):
        return false

    // 4. Envelope ID recomputation
    tmp = clone(envelope)
    sig = tmp.signature_pq
    tmp.signature_pq = null
    bytes = canonical_encode(tmp)
    expected_id = pqvl_hash_with_domain("PQVL-Attestation", bytes)
    if envelope.envelope_id != expected_id:
        return false

    return true
```

## **4.5 Required Probes per Enforcement**

PQHD and PQAI MUST treat the following as mandatory:

* `system_state`
* `process_state`
* `integrity_state`

`policy_state` SHOULD be mandatory where local policy modules exist.

### Pseudocode (Informative) — Required Probe Check

```
// Ensure all required probe types are present
function pqvl_has_required_probes(probes):
    required = ["system_state", "process_state", "integrity_state"]
    types_present = set([p.probe_type for p in probes])

    for r in required:
        if r not in types_present:
            return false

    return true
```

---

# **5. DRIFT CLASSIFICATION & SEMANTICS (NORMATIVE)**

PQVL MUST classify runtime integrity according to deterministic evaluation of ProbeResults.

## **5.1 Drift States**

PQVL MUST use the following drift states:

* **NONE** — all probes valid, all baselines matched.
* **WARNING** — at least one probe reports `status = "warning"`, but no integrity violations.
* **CRITICAL** — any required probe reports `status = "invalid"` or any probe baseline mismatch occurs.

## **5.2 Drift Predicate**

PQVL MUST compute `drift_state` using the following deterministic rules:

    drift_state = CRITICAL    if any required probe has status == "invalid"
    drift_state = WARNING     if no required probe is invalid AND at least one probe has status == "warning"
    drift_state = NONE        otherwise

### **Pseudocode (Informative) — Drift Classification Core**

// Classify drift based on probe statuses
function pqvl_classify_drift_from_statuses(probes):
    required_types = ["system_state", "process_state", "integrity_state"]
    has_warning = false

    for p in probes:
        if p.probe_type in required_types and p.status == "invalid":
            return "CRITICAL"
        if p.status == "warning":
            has_warning = true

    if has_warning:
        return "WARNING"

    return "NONE"

## **5.3 Impact on Consumers**

* If `drift_state = CRITICAL`, PQSF, PQHD, and PQAI MUST treat the runtime as invalid and fail closed.
* If `drift_state = WARNING`, PQHD and PQAI MUST restrict high-risk flows but MAY allow low-risk operations.
* If `drift_state = NONE`, consumers MAY proceed normally.

## **5.4 Required Probe Baseline Comparison**

ProbeResults MUST be checked against an expected baseline:

```
baseline_hash = SHAKE256-256(canonical(expected_probe_details))
current_hash  = SHAKE256-256(canonical(ProbeResult.details))
```

If `baseline_hash != current_hash`, PQVL MUST treat the probe as `invalid` unless the discrepancy is explicitly classified as “warning”.

### Pseudocode (Informative) — Baseline Comparison

```
// Compare ProbeResult.details to an expected baseline
function pqvl_compare_probe_to_baseline(probe, baseline_details):
    baseline_bytes = canonical_encode(baseline_details)
    current_bytes  = canonical_encode(probe.details)

    baseline_hash = shake256_256(baseline_bytes)
    current_hash  = shake256_256(current_bytes)

    if baseline_hash == current_hash:
        return "valid"

    // Implementation may classify specific differences as "warning"
    if is_tolerable_difference(probe.probe_type, probe.details, baseline_details):
        return "warning"

    return "invalid"
```

## **5.5 Drift MUST Fail-Closed**

If drift_state transitions to CRITICAL:

* PQVL MUST include this in AttestationEnvelope
* PQVL MUST block further attestation generation until baseline is reloaded or drift resolved
* PQVL MUST require fresh PQSF Tick before resuming
* PQSF, PQHD, and PQAI MUST treat all dependent predicates as invalid

### Pseudocode (Informative) — Attestation Freeze on CRITICAL Drift

```
// Enforce freeze when drift_state becomes CRITICAL
function pqvl_handle_critical_drift(env, envelope):
    if envelope.drift_state != "CRITICAL":
        return

    env.attestation_frozen = true
    PQSF.ledger_append_runtime_event(envelope)

    // Subsequent calls must refuse to attest until reset
    // env.attestation_frozen can only be cleared by governance action
```

---

# **6. PQSF INTEGRATION (NORMATIVE)**

PQVL MUST integrate tightly with PQSF’s transport, tick, probe, and ledger components.

## **6.1 Probe API Integration**

PQVL MUST expose AttestationEnvelope to PQSF via the Probe API using probe type:

```
"runtime.verification"
```

The probe response MUST contain:

* the full AttestationEnvelope
* canonical encoding
* ML-DSA signature
* current Epoch Tick

### Pseudocode (Informative) — Probe Handler

```
// PQSF probe handler for runtime.verification
function probe_runtime_verification(env):
    if env.attestation_frozen:
        return error("E_RUNTIME_DRIFT_CRITICAL")

    envelope = pqvl_attest_runtime(env)
    return canonical_encode(envelope)
```

## **6.2 Tick Validation**

PQVL MUST validate attestation freshness using authenticated Epoch Clock ticks only.

An AttestationEnvelope is valid **only if**:

    envelope.tick >= current_tick - attestation_window

The default `attestation_window` is **900 seconds** unless a PQSF-compliant
deployment applies a stricter bound.

PQVL implementations MUST NOT use system time (RTC, NTP, OS time APIs) for any
freshness or temporal validation. All time semantics MUST derive exclusively from
verifiable EpochTicks supplied by PQSF transport or an authenticated local tick cache.

### **Pseudocode (Informative) — Enforcing Tick Rules**

// Validate attestation tick using Epoch Clock ticks only
function pqvl_enforce_tick_rules(envelope, current_tick, window):
    if envelope.tick > current_tick:
        return false    // future tick: invalid
    if envelope.tick < current_tick - window:
        return false    // stale tick
    return true

## **6.3 Exporter Binding**

If PQSF transport provides an exporter_hash, PQVL MUST embed:

```
"exporter_hash": <bytes>
```

in AttestationEnvelope.

Consumers MUST treat attestation as invalid if exporter_hash mismatches.

### Pseudocode (Informative) — Exporter Binding

```
// Verify that AttestationEnvelope is bound to the correct exporter_hash
function pqvl_check_exporter_binding(envelope, session_exporter_hash):
    if envelope.exporter_hash is null:
        return true  // binding not used

    return (envelope.exporter_hash == session_exporter_hash)
```

## **6.4 Ledger Integration**

PQVL MUST record to the PQSF ledger:

* `runtime_attested`
* `runtime_drift_warning`
* `runtime_drift_critical`

Each entry MUST include:

* tick
* drift_state
* probe summary
* envelope_id

### Pseudocode (Informative) — Writing Ledger Events

```
// Append runtime_attested / drift events to PQSF ledger
function pqvl_ledger_record(envelope):
    event_type = "runtime_attested"
    if envelope.drift_state == "WARNING":
        event_type = "runtime_drift_warning"
    if envelope.drift_state == "CRITICAL":
        event_type = "runtime_drift_critical"

    summary = {
        envelope_id: envelope.envelope_id,
        drift_state: envelope.drift_state,
        probe_count: len(envelope.probes)
    }

    entry = {
        event:   event_type,
        tick:    envelope.tick,
        payload: summary
    }

    bytes = canonical_encode(entry)
    entry.signature_pq = sign_pq(get_ledger_sk(), bytes)
    PQSF.ledger_append(entry)
```

## **6.5 Fail-Closed Enforcement**

PQSF MUST set:

```
valid_runtime = false
```

if:

* PQVL attestation invalid
* drift_state = CRITICAL
* tick stale
* canonical encoding invalid
* signature invalid

---

# **7. PQHD INTEGRATION (NORMATIVE)**

PQHD MUST use PQVL to determine `valid_device`.

## **7.1 Required Condition**

Before any signing attempt, PQHD MUST evaluate:

```
valid_device = (PQVL.drift_state == "NONE")
```

If false → PQHD MUST NOT sign.

### Pseudocode (Informative) — Signing Gate in PQHD

```
// PQHD signing gate based on PQVL
function pqhd_maybe_sign(psbt, env):
    att = PQSF.get_probe("runtime.verification", env.device_id)
    if not pqvl_validate_envelope(att, env.current_tick, env.attestation_window):
        return error("E_RUNTIME_INVALID")

    if att.drift_state != "NONE":
        return error("E_RUNTIME_DRIFT_CRITICAL")

    return pqhd_sign_psbt(psbt)
```

## **7.2 Continuous Predicate-Scoped Checks**

PQHD MUST request a fresh PQVL attestation **immediately before** evaluating:

* PSBT canonicalisation
* bundle_hash computation
* Policy Enforcer evaluation
* consent validation
* quorum validation
* key derivation
* signature production

## **7.3 Impact on Recovery & Secure Import**

Recovery and Secure Import MUST treat any PQVL drift as:

```
valid_device = false
```

and MUST NOT proceed.

## **7.4 Canonical PQVL Handling**

PQHD MUST reject AttestationEnvelopes if:

* canonicalisation fails
* any required probe missing
* signature invalid
* drift_state = CRITICAL
* tick invalid

---

# **8. PQAI INTEGRATION (NORMATIVE)**

PQAI MUST use PQVL to implement `valid_runtime`.

## **8.1 Required Condition**

Before evaluating any PQAI predicate:

```
valid_runtime = (PQVL.drift_state == "NONE")
```

PQAI MUST NOT:

* generate fingerprints
* evaluate drift
* execute safe prompts
* assist PQHD in high-risk flows

unless runtime is valid.

## **8.2 PQVL Enforcement During Fingerprinting**

PQAI MUST require a fresh PQVL attestation before:

* generating a fingerprint
* validating fingerprints
* updating ModelProfile
* classifying drift

If PQVL indicates ANY invalid condition → PQAI MUST classify drift as CRITICAL.

## **8.3 PQVL Enforcement During Safe-Prompt Flows**

Before evaluating a SafePrompt:

* PQVL MUST validate runtime
* tick MUST be fresh
* drift_state MUST NOT be CRITICAL

## **8.4 PQAI Probe API Integration**

PQVL MUST expose a probe type:

```
"runtime.state"
```

PQAI MUST treat this probe as authoritative for runtime integrity.

### Pseudocode (Informative) — PQAI Use of runtime.state Probe

```
// PQAI using runtime.state probe as a fast-check
function pqai_check_runtime_state(env):
    state = PQSF.get_probe("runtime.state", env.device_id)
    if state.drift_state != "NONE":
        return false
    return true
```

---

# **9. TRANSPORT REQUIREMENTS (NORMATIVE)**

## **9.1 Deterministic Transport**

AttestationEnvelopes MUST be transmitted over:

* TLSE-EMP, or
* STP

Transport MUST NOT permit:

* session replay
* canonicalisation drift
* unverified exporter_hash

### Pseudocode (Informative) — Transport Send

```
// Send AttestationEnvelope over a PQSF transport session
function pqvl_send_envelope_over_transport(envelope, session):
    payload = canonical_encode(envelope)
    session.send(payload)  // TLSE-EMP or STP
```

## **9.2 Offline Operation**

PQVL MUST support offline verification:

* cached tick valid for ≤900 seconds
* cached baselines
* local verification of ProbeResults
* no reliance on network connectivity

## **9.3 Stealth Mode**

In Stealth Mode:

* PQVL MUST function without DNS or remote calls
* attestation freshness MUST use cached tick
* drift detection MUST still operate

### Pseudocode (Informative) — Offline Tick Use

```
// Use cached tick for offline mode with a strict limit
function pqvl_get_tick_offline(cache):
    if cache.age_seconds > 900:
        return error("E_TICK_STALE")
    return cache.tick
```

---

# **10. CANONICALISATION RULES (NORMATIVE)**

## **10.1 Canonical AttestationEncoding**

AttestationEnvelope MUST be canonicalised using:

* deterministic CBOR, or
* JCS JSON

Consumers MUST reject envelopes that differ byte-for-byte when canonicalised.

## **10.2 Probe Canonicalisation**

Each ProbeResult MUST be canonicalised before:

* hashing
* inclusion in AttestationEnvelope
* drift evaluation

## **10.3 Baseline Hash Canonicalisation**

Expected baselines MUST be canonical prior to hashing.

### Pseudocode (Informative) — Canonicality Check Helper

```
// Verify that an envelope decodes and re-encodes to the same bytes
function pqvl_is_canonical(envelope_bytes):
    decoded = decode(envelope_bytes)
    reencoded = canonical_encode(decoded)
    return (reencoded == envelope_bytes)
```

---

# **11. ERROR CODES (NORMATIVE)**

PQVL MUST define, at minimum:

```
E_RUNTIME_INVALID
E_RUNTIME_STALE
E_RUNTIME_DRIFT_CRITICAL
E_RUNTIME_DRIFT_WARNING
E_PROBE_MISSING
E_PROBE_INVALID
E_PROBE_NONCANONICAL
E_SIGNATURE_INVALID
E_TICK_INVALID
E_TICK_STALE
E_EXPORTER_MISMATCH
```

### Pseudocode (Informative) — Mapping Conditions to Errors

```
// Map common PQVL validation failures to error codes
function pqvl_error_from_context(ctx):
    if ctx.signature_invalid:
        return "E_SIGNATURE_INVALID"
    if ctx.tick_invalid:
        return "E_TICK_INVALID"
    if ctx.tick_stale:
        return "E_TICK_STALE"
    if ctx.probe_missing:
        return "E_PROBE_MISSING"
    if ctx.probe_noncanonical:
        return "E_PROBE_NONCANONICAL"
    if ctx.exporter_mismatch:
        return "E_EXPORTER_MISMATCH"
    if ctx.drift_state == "CRITICAL":
        return "E_RUNTIME_DRIFT_CRITICAL"
    if ctx.drift_state == "WARNING":
        return "E_RUNTIME_DRIFT_WARNING"
    if ctx.runtime_stale:
        return "E_RUNTIME_STALE"
    return "E_RUNTIME_INVALID"
```

---

# **12. SECURITY CONSIDERATIONS (INFORMATIVE)**

* PQVL detects runtime compromise early.
* Drift classification prevents unsafe operation.
* Canonical encoding prevents data-structure attacks.
* PQVL prevents weakened PQHD/PQAI predicates.
* Tick binding enables replay protection.

---

# **13. IMPLEMENTATION NOTES (INFORMATIVE)**

* Probes may use OS APIs, hash files, check processes, or verify sandbox integrity.
* PQVL is OS-neutral.
* Implementations should minimise probe nondeterminism.
* Drift baselines should be stored securely.

---

# **14. BACKWARDS COMPATIBILITY (INFORMATIVE)**

* PQVL does not require TPMs, TEEs, or specific OS features.
* Runs on Linux, macOS, Windows, iOS, Android, embedded systems.
* Compatible with offline and sovereign deployments.

---

# **ANNEX A — Probe Examples (INFORMATIVE)**

Annex A provides examples of PQVL probe structures.
These examples illustrate typical usage but MUST NOT override the normative requirements defined in §4.

## **A.1 system_state Probe Example**

```
ProbeResult = {
  "probe_type": "system_state",
  "status": "valid",
  "details": {
    "kernel_version": "6.5.0",
    "security_patches_missing": 0,
    "selinux_mode": "enforcing"
  },
  "tick": 1730000000
}
```

## **A.2 process_state Probe Example**

```
ProbeResult = {
  "probe_type": "process_state",
  "status": "valid",
  "details": {
    "expected_process": "pqhd-signer",
    "running": true,
    "unexpected_processes": []
  },
  "tick": 1730000000
}
```

## **A.3 integrity_state Probe Example**

```
ProbeResult = {
  "probe_type": "integrity_state",
  "status": "warning",
  "details": {
    "binary_hash": "0xa1b2c3...",
    "expected_hash": "0xa1b2c3...",
    "config_hash_mismatch": false
  },
  "tick": 1730000000
}
```

## **A.4 policy_state Probe Example**

```
ProbeResult = {
  "probe_type": "policy_state",
  "status": "valid",
  "details": {
    "firewall_enabled": true,
    "mandatory_policies_active": ["sandbox", "isolation"]
  },
  "tick": 1730000000
}
```

---

# **ANNEX B — Attestation & Drift Examples (INFORMATIVE)**

Annex B provides examples of AttestationEnvelopes and drift classifications for developer reference.

## **B.1 Example AttestationEnvelope (drift_state = NONE)**

```
AttestationEnvelope = {
  "envelope_id": "0xd88cac07...",
  "probes": [
      { "probe_type": "system_state", "status": "valid", "details": {...}, "tick": 1730000000 },
      { "probe_type": "process_state", "status": "valid", "details": {...}, "tick": 1730000000 },
      { "probe_type": "integrity_state","status": "valid", "details": {...}, "tick": 1730000000 }
  ],
  "drift_state": "NONE",
  "tick": 1730000000,
  "signature_pq": "<ML-DSA-65 signature>"
}
```

## **B.2 Drift Warning Example**

```
AttestationEnvelope = {
  "envelope_id": "0xfaa13301...",
  "probes": [
      { "probe_type": "integrity_state", "status": "warning", "details": {...}, "tick": 1730000100 },
      { "probe_type": "system_state", "status": "valid"  , "details": {...}, "tick": 1730000100 },
      { "probe_type": "process_state","status": "valid"  , "details": {...}, "tick": 1730000100 }
  ],
  "drift_state": "WARNING",
  "tick": 1730000100,
  "signature_pq": "<ML-DSA-65 signature>"
}
```

## **B.3 Drift Critical Example**

```
AttestationEnvelope = {
  "envelope_id": "0xb99192fe...",
  "probes": [
      { "probe_type": "system_state", "status": "invalid", "details": {"selinux_mode": "disabled"}, "tick": 1730000200 }
  ],
  "drift_state": "CRITICAL",
  "tick": 1730000200,
  "signature_pq": "<ML-DSA-65 signature>"
}
```

Under CRITICAL drift, PQSF, PQHD, and PQAI MUST fail-closed.

---

# **ANNEX C — Developer Workflow Examples (INFORMATIVE)**

Annex C provides typical end-to-end workflows for developers implementing PQVL.

## **C.1 Attestation Generation Workflow**

1. Collect OS data for all required probes.
2. Construct ProbeResult objects.
3. Canonicalise ProbeResult objects.
4. Evaluate drift state (NONE / WARNING / CRITICAL).
5. Build AttestationEnvelope:

   * probes
   * drift_state
   * tick
   * envelope_id
6. Sign envelope with ML-DSA-65.
7. Return to PQSF/PQHD/PQAI.

### Pseudocode (Informative) — End-to-End Generation

```
// End-to-end generation wrapper
function pqvl_generate_and_publish(env):
    envelope = pqvl_attest_runtime(env)
    pqvl_ledger_record(envelope)
    PQSF.publish_probe("runtime.verification", envelope)
    return envelope
```

## **C.2 Attestation Validation Workflow (Consumer Side)**

1. Validate ML-DSA-65 signature.

2. Validate canonical encoding.

3. Validate tick freshness.

4. Validate required probes exist.

5. Evaluate drift_state:

   * if WARNING → restrict high-risk operations
   * if CRITICAL → fail closed

6. Commit ledger entry if required.

### Pseudocode (Informative) — Consumer Validation Wrapper

```
// Consumer-side validation
function consumer_validate_runtime(envelope, current_tick, window):
    if not pqvl_validate_envelope(envelope, current_tick, window):
        return { valid_runtime: false, error: "E_RUNTIME_INVALID" }

    if envelope.drift_state == "CRITICAL":
        return { valid_runtime: false, error: "E_RUNTIME_DRIFT_CRITICAL" }

    return { valid_runtime: true, warning: envelope.drift_state == "WARNING" }
```

## **C.3 Runtime Drift Recovery Workflow**

1. PQVL detects drift WARNING or CRITICAL.
2. Freeze attestation generation (CRITICAL only).
3. Refresh or reload expected baseline.
4. Rerun probes.
5. Recompute drift_state.
6. When drift resolved → allow normal operation.

## **C.4 Continuous Attestation Workflow**

Used by PQHD, PQAI, and PQSF.

1. Before each predicate:

   * Request PQVL attestation
   * Validate runtime integrity
   * Reject stale envelopes

2. Evaluate predicate (policy, signing, fingerprint).

3. Repeat for each predicate in the sequence.

---


## **Acknowledgements (Informative)**

This specification acknowledges the foundational contributions of:

Peter Shor, whose algorithm motivates post-quantum-secure signatures for attestation.

Ralph Merkle, for Merkle tree constructions that inform deterministic logging and integrity-state verification.

Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche, inventors of Keccak, the basis for SHAKE-family hashing used in probe and envelope hashing.

These contributions underpin the post-quantum and deterministic verification model defined in PQVL.

---

If you find this work useful and want to support it, you can do so here:
bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw
