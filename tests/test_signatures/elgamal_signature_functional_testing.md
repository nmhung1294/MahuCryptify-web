# ELGAMAL DIGITAL SIGNATURE - FUNCTIONAL TEST PLAN

## 1. ELGAMAL SIGNING TESTS

### 1.1. Basic Signing (10 tests)

| Test ID | Description | Message | Bits | Expected | Priority |
|---------|-------------|---------|------|----------|----------|
| TC_ELG_SIG_001 | Sign "HELLO" | "HELLO" | 32 | Success, returns signature + hash | HIGH |
| TC_ELG_SIG_002 | Sign "TEST" | "TEST" | 32 | Success, 1 block (4 chars) | HIGH |
| TC_ELG_SIG_003 | Sign single char | "A" | 32 | Success, 1 signature | MEDIUM |
| TC_ELG_SIG_004 | Sign multiple blocks | "HELLOWORLD" | 32 | Success, 3 blocks | HIGH |
| TC_ELG_SIG_005 | Sign long text | "A"*20 | 32 | Success, 5 blocks | MEDIUM |
| TC_ELG_SIG_006 | Sign with 16 bits | "TEST" | 16 | Success (fast) | MEDIUM |
| TC_ELG_SIG_007 | Sign with 64 bits | "TEST" | 64 | Success (may be slow) | MEDIUM |
| TC_ELG_SIG_008 | Sign result format | "TEST" | 32 | Contains tuples (γ, δ) | HIGH |
| TC_ELG_SIG_009 | Sign with special chars | "TEST!@#" | 32 | pre_solve removes special chars | MEDIUM |
| TC_ELG_SIG_010 | Sign lowercase | "test" | 32 | Converts to uppercase | MEDIUM |

### 1.2. Text Processing (4 tests)

| Test ID | Description | Input | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_ELG_SIG_T001 | Special characters removed | "HELLO!@#$" | Only "HELLO" signed | HIGH |
| TC_ELG_SIG_T002 | Numbers removed | "TEST123" | Only "TEST" signed | MEDIUM |
| TC_ELG_SIG_T003 | Spaces handling | "HELLO WORLD" | Spaces removed/handled | MEDIUM |
| TC_ELG_SIG_T004 | Mixed case | "HeLLo" | Converts to "HELLO" | MEDIUM |

### 1.3. Signing Error Tests (11 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_ELG_SIG_E001 | Null message | message=None | "NULL Value" | HIGH |
| TC_ELG_SIG_E002 | Empty message | message="" | "NULL Value" | HIGH |
| TC_ELG_SIG_E003 | Null p | p=None | "NULL Value" | HIGH |
| TC_ELG_SIG_E004 | Null alpha | alpha=None | "NULL Value" | HIGH |
| TC_ELG_SIG_E005 | Null a | a=None | "NULL Value" | HIGH |
| TC_ELG_SIG_E006 | p not prime | p=100 | "p is not prime" | HIGH |
| TC_ELG_SIG_E007 | alpha not primitive root | alpha=3, p=7 | "alpha is not primitive root" | HIGH |
| TC_ELG_SIG_E008 | p = 0 | p=0 | "NULL Value" | HIGH |
| TC_ELG_SIG_E009 | alpha = 0 | alpha=0 | "NULL Value" | HIGH |
| TC_ELG_SIG_E010 | a = 0 | a=0 | "NULL Value" | HIGH |
| TC_ELG_SIG_E011 | Invalid types | p="abc" | "p, alpha, a must be integers" | HIGH |

---

## 2. ELGAMAL VERIFICATION TESTS

### 2.1. Basic Verification (8 tests)

| Test ID | Description | Setup | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_ELG_VER_001 | Verify valid signature | Sign "TEST" → Verify | True | HIGH |
| TC_ELG_VER_002 | Verify multiple blocks | Sign "HELLO" → Verify | True | HIGH |
| TC_ELG_VER_003 | Verify with correct keys | Sign with a, verify with β | True | HIGH |
| TC_ELG_VER_004 | Verify single block | Sign "TEST" (1 block) → Verify | True | HIGH |
| TC_ELG_VER_005 | Verify long message | Sign "A"*20 → Verify | True | MEDIUM |
| TC_ELG_VER_006 | Verify with wrong signature | Modify signature → Verify | False | HIGH |
| TC_ELG_VER_007 | Verify with wrong message | Sign "TEST", verify with different hash | False | HIGH |
| TC_ELG_VER_008 | Verify with wrong keys | Sign with keys1, verify with keys2 | False | HIGH |

### 2.2. Verification Error Tests (5 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_ELG_VER_E001 | Null hash | hash=None | "NULL Value" | HIGH |
| TC_ELG_VER_E002 | Empty hash | hash="" | "NULL Value" | HIGH |
| TC_ELG_VER_E003 | Null signature | signed=None | "NULL Value" | HIGH |
| TC_ELG_VER_E004 | Null p | p=None | "NULL Value" | HIGH |
| TC_ELG_VER_E005 | Null alpha | alpha=None | "NULL Value" | HIGH |

---

## 3. INTEGRATION TESTS

### 3.1. Full Cycle Tests (6 tests)

| Test ID | Description | Flow | Bits | Expected | Priority |
|---------|-------------|------|------|----------|----------|
| TC_ELG_INT_001 | Full cycle Sign→Verify | Gen keys → Sign "TEST" → Verify | 32 | Verify returns True | HIGH |
| TC_ELG_INT_002 | Cycle with 16 bits | Gen(16) → Sign "TEST" → Verify | 16 | True | MEDIUM |
| TC_ELG_INT_003 | Cycle with 64 bits | Gen(64) → Sign "TEST" → Verify | 64 | True | MEDIUM |
| TC_ELG_INT_004 | Multiple messages | Gen → Sign 3 messages → Verify all | 32 | All True | MEDIUM |
| TC_ELG_INT_005 | Sign twice same message | Sign "TEST" twice → Compare | 32 | Different signatures (probabilistic) | MEDIUM |
| TC_ELG_INT_006 | Cross-key test | Keys1 sign, Keys2 verify | 32 | False | MEDIUM |

---

## 4. MATHEMATICAL PROPERTIES

### 4.1. ElGamal Signature Properties (6 tests)

| Test ID | Description | Test | Expected | Priority |
|---------|-------------|------|----------|----------|
| TC_ELG_MATH_001 | Gamma formula | γ = α^k mod p | Correct gamma | HIGH |
| TC_ELG_MATH_002 | Delta formula | δ = (M - a×γ) × k^(-1) mod (p-1) | Correct delta | HIGH |
| TC_ELG_MATH_003 | Verification formula | β^γ × γ^δ ≡ α^M (mod p) | True for valid sig | HIGH |
| TC_ELG_MATH_004 | Signature format | Check (γ, δ) tuples | Correct format | MEDIUM |
| TC_ELG_MATH_005 | Invalid signature detection | Modify γ or δ | Verify returns False | HIGH |
| TC_ELG_MATH_006 | Same k for all blocks | Implementation detail | All γ values same | LOW |

---

## 5. EDGE CASES

### 5.1. Edge Cases (5 tests)

| Test ID | Description | Input | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_ELG_EDGE_001 | Very small p (16 bits) | Sign with 16-bit keys | Works but insecure | MEDIUM |
| TC_ELG_EDGE_002 | Message boundary | Message length = 4k chars | Works correctly | LOW |
| TC_ELG_EDGE_003 | Empty after preprocessing | "123!@#" (no letters) | Empty or error | MEDIUM |
| TC_ELG_EDGE_004 | Alpha = 2 validation | Check α=2 is primitive root | May fail for some p | LOW |
| TC_ELG_EDGE_005 | Large a value | a = p - 2 | Should work (valid range) | LOW |
