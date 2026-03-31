# Detailed Project Explanation

## 1) Project Title

PGP Key Signing with Weak Hash (MD5): Collision-Based Signature Forgery and Secure Prevention

---

## 2) Problem Statement

This project demonstrates a core security weakness in digital signature workflows:

- If a weak hash function like MD5 is used before signing, collision-style forgery becomes possible.
- If two different inputs can be made to map to the same digest, a signature created for one input may be accepted for another.
- This breaks trust assumptions in systems similar to PGP key-signing.

The project then applies prevention by enforcing strong hash functions and measuring security improvement.

---

## 3) High-Level Objective

1. Simulate vulnerable signing flow using MD5.
2. Show high forgery success before prevention.
3. Enforce strong hash prevention methods.
4. Show forgery success drops to 0% after prevention.
5. Present comparative analysis through required and additional graphs.

---

## 4) Implemented Prevention Methods

The project supports four secure prevention methods:

1. SHA-256
2. SHA3-256
3. SHA-512
4. BLAKE2B-256

MD5 acts as baseline vulnerable mode.

---

## 5) Architecture and Module Roles

### Core Layer

- src/core/rsa_core.py
  - RSA key generation, sign, verify
  - Prime generation + modular inverse math
- src/core/md5_core.py
  - Custom MD5 implementation (educational baseline)

### Experiment Layer

- src/attack/experiment_engine.py
  - Runs automated suites (25 test cases)
  - Computes success rate, integrity/authentication rates, and latency metrics
  - Handles all prevention modes
  - Supports per-case callbacks for live GUI logging

- src/attack/attack_simulation.py
  - CLI entry logic for before/after summary display

### GUI Layer

- src/gui/gui.py
  - Tkinter dashboard
  - Buttons: Generate Keys, Run Attack, Apply Prevention, Show Graphs
  - Prevention method selector
  - Color-coded logs (red vulnerable, green secure)
  - Graph viewer window to display generated PNG images

### Analysis Layer

- src/analysis/graphs.py
  - Generates mandatory graph set
  - Generates additional comparative graph set
  - Produces separate PNGs + combined mandatory dashboard

### Launchers

- scripts/run_gui.py
- scripts/run_attack.py
- scripts/run_graphs.py

---

## 6) End-to-End Execution Flow

1. User launches GUI.
2. User generates RSA keys.
3. In MD5 mode, attack suite runs 25 cases and reports high forgery success.
4. User selects a prevention method and applies prevention.
5. Prevention suite runs 25 cases and reports secure behavior.
6. User clicks Show Graphs.
7. Graph package is generated and displayed in a separate viewer window.

---

## 7) Mathematical Intuition

Digital signature flow is modeled as:

S = Sign(K_pr, H(M))

Verification checks:

Verify(K_pub, S) == H(M)

If an attacker can create different messages M and M' such that:

H(M) = H(M')

then signature S from M can be reused for M'.

This is why collision resistance of H is critical.

- MD5 (128-bit) is considered collision-broken in modern cryptography.
- Strong alternatives increase resistance and block practical forgery in this model.

---

## 8) Test Design

- 25 automated test cases per mode.
- Varying RSA key sizes in cycle (1024, 1536, 2048).
- For each case:
  - Build legitimate + malicious payloads
  - Hash, sign, verify
  - Record result and timings

Measured metrics include:

- Forgery success rate
- Integrity rate
- Authentication rate
- Average hash latency
- Average sign latency
- Average verify latency

---

## 9) Graph Output Design

### Mandatory Graphs

1. Attack success rate (MD5 vs 4 prevention methods)
2. Time vs key/parameter size
3. CIA rate comparison
4. Attack vs prevention latency overhead

Also generated:

- Combined mandatory dashboard (4-in-1)

### Additional Graphs

- Method-wise success trend
- Hash latency comparison
- End-to-end latency comparison
- Security improvement vs MD5 baseline

---

## 10) Security Interpretation

Expected behavior from runs:

- MD5 baseline shows high forgery acceptance.
- All prevention methods target 0% forgery success.
- Integrity/authentication rates increase significantly under prevention modes.

This directly demonstrates that replacing weak hash primitives materially improves signature trustworthiness.

---

## 11) Demo Guidance (Short)

Recommended live sequence:

1. Generate keys
2. Run attack in MD5 mode
3. Apply prevention with selected method
4. Re-run tests
5. Show graphs and open graph viewer

Focus statement for viva:

"The same signing mechanism is used throughout; only the hash primitive changes. The measured drop from vulnerable forgery success to secure 0% demonstrates hash-strength impact on signature security."

---

## 12) Limitations and Scope

- This is an educational simulation for comparative understanding.
- Real-world cryptosystems include additional constraints and hardened formats.
- The project intentionally keeps attack/prevention behavior observable for teaching and review analysis.

---

## 13) Conclusion

The project successfully demonstrates:

- Why weak hash usage in signing pipelines is dangerous
- How prevention through strong hash enforcement mitigates forgery
- How to support evidence-based security claims using automated tests and visual analysis

It provides both technical implementation and presentation-ready outputs for final review.
