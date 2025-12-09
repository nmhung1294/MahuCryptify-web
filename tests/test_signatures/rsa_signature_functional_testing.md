# RSA DIGITAL SIGNATURE - FUNCTIONAL TEST PLAN

## 1. RSA SIGNING TESTS

### 1.1. Basic Signing (10 tests)

| Test ID | Description | Message | Bits | Expected | Priority |
|---------|-------------|---------|------|----------|----------|
| TC_RSA_SIG_001 | Sign "HELLO" | "HELLO" | 32 | Success, returns signature + hash | HIGH |
| TC_RSA_SIG_002 | Sign "TEST" | "TEST" | 32 | Success, 1 block (4 chars) | HIGH |
| TC_RSA_SIG_003 | Sign single char | "A" | 32 | Success, 1 signature | MEDIUM |
| TC_RSA_SIG_004 | Sign multiple blocks | "HELLOWORLD" | 32 | Success, 3 blocks | HIGH |
| TC_RSA_SIG_005 | Sign long text | "A"*20 | 32 | Success, 5 blocks | MEDIUM |
| TC_RSA_SIG_006 | Sign with 16 bits | "TEST" | 16 | Success (fast) | MEDIUM |
| TC_RSA_SIG_007 | Sign with 64 bits | "TEST" | 64 | Success (may be slow) | MEDIUM |
| TC_RSA_SIG_008 | Sign result format | "TEST" | 32 | Contains "Signed Message" and "Hashed Message" | HIGH |
| TC_RSA_SIG_009 | Sign with special chars | "TEST!@#" | 32 | pre_solve removes special chars | MEDIUM |
| TC_RSA_SIG_010 | Sign lowercase | "test" | 32 | Converts to uppercase | MEDIUM |

### 1.2. Text Processing (4 tests)
| Test ID | Description | Input | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_RSA_SIG_T001 | Special characters removed | "HELLO!@#$" | Only "HELLO" signed | HIGH |
| TC_RSA_SIG_T002 | Numbers removed | "TEST123" | Only "TEST" signed | MEDIUM |
| TC_RSA_SIG_T003 | Spaces handling | "HELLO WORLD" | Spaces removed/handled | MEDIUM |
| TC_RSA_SIG_T004 | Mixed case | "HeLLo" | Converts to "HELLO" | MEDIUM |

### 1.3. Signing Error Tests (11 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_RSA_SIG_E001 | Null message | message=None | "Enter Again" or "NULL Value" | HIGH |
| TC_RSA_SIG_E002 | Empty message | message="" | "Enter Again" or "NULL Value" | HIGH |
| TC_RSA_SIG_E003 | Null p | p=None | "Enter Again" | HIGH |
| TC_RSA_SIG_E004 | Null q | q=None | "Enter Again" | HIGH |
| TC_RSA_SIG_E005 | Null d | d=None | "Enter Again" | HIGH |
| TC_RSA_SIG_E006 | p not prime | p=100 | "p or q is not prime" | HIGH |
| TC_RSA_SIG_E007 | q not prime | q=100 | "p or q is not prime" | HIGH |
| TC_RSA_SIG_E008 | p = q | p=q=prime | Error (implementation may not check) | MEDIUM |
| TC_RSA_SIG_E009 | d = 0 | d=0 | "Enter Again" | HIGH |
| TC_RSA_SIG_E010 | d > n | d > p*q | "Enter Again" | HIGH |
| TC_RSA_SIG_E011 | Invalid types | p="abc" | "p, q, d must be integers" | HIGH |

---

## 2. RSA VERIFICATION TESTS

### 2.1. Basic Verification (8 tests)

| Test ID | Description | Setup | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_RSA_VER_001 | Verify valid signature | Sign "TEST" → Verify | True | HIGH |
| TC_RSA_VER_002 | Verify multiple blocks | Sign "HELLO" → Verify | True | HIGH |
| TC_RSA_VER_003 | Verify with correct keys | Sign with d, verify with e | True | HIGH |
| TC_RSA_VER_004 | Verify single block | Sign "TEST" (1 block) → Verify | True | HIGH |
| TC_RSA_VER_005 | Verify long message | Sign "A"*20 → Verify | True | MEDIUM |
| TC_RSA_VER_006 | Verify with wrong signature | Modify signature → Verify | False | HIGH |
| TC_RSA_VER_007 | Verify with wrong message | Sign "TEST", verify with different hash | False | HIGH |
| TC_RSA_VER_008 | Verify with wrong keys | Sign with keys1, verify with keys2 | False | HIGH |

### 2.2. Verification Error Tests (5 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_RSA_VER_E001 | Null hash | hash=None | "Enter Again" | HIGH |
| TC_RSA_VER_E002 | Empty hash | hash="" | "Enter Again" | HIGH |
| TC_RSA_VER_E003 | Null signature | signed=None | "Enter Again" | HIGH |
| TC_RSA_VER_E004 | Null n | n=None | "Enter Again" | HIGH |
| TC_RSA_VER_E005 | Null e | e=None | "Enter Again" | HIGH |

---

## 3. INTEGRATION TESTS

### 3.1. Full Cycle Tests (6 tests)

| Test ID | Description | Flow | Bits | Expected | Priority |
|---------|-------------|------|------|----------|----------|
| TC_RSA_INT_001 | Full cycle Sign→Verify | Gen keys → Sign "TEST" → Verify | 32 | Verify returns True | HIGH |
| TC_RSA_INT_002 | Cycle with 16 bits | Gen(16) → Sign "TEST" → Verify | 16 | True | MEDIUM |
| TC_RSA_INT_003 | Cycle with 64 bits | Gen(64) → Sign "TEST" → Verify | 64 | True | MEDIUM |
| TC_RSA_INT_004 | Multiple messages | Gen → Sign 3 messages → Verify all | 32 | All True | MEDIUM |
| TC_RSA_INT_005 | Sign twice same message | Sign "TEST" twice → Verify both | 32 | Both True, same signature | LOW |
| TC_RSA_INT_006 | Cross-key test | Keys1 sign, Keys2 verify | 32 | False | MEDIUM |

---

## 4. MATHEMATICAL PROPERTIES

### 4.1. RSA Signature Properties (5 tests)

| Test ID | Description | Test | Expected | Priority |
|---------|-------------|------|----------|----------|
| TC_RSA_MATH_001 | Sign formula | S = M^d mod n | Correct signature | HIGH |
| TC_RSA_MATH_002 | Verify formula | M = S^e mod n | Recovers hash | HIGH |
| TC_RSA_MATH_003 | Signature deterministic | Sign "TEST" twice → same signature | Same signature both times | HIGH |
| TC_RSA_MATH_004 | Signature size = hash size | len(signature) == len(hash) | True | MEDIUM |
| TC_RSA_MATH_005 | Invalid signature detection | Modify 1 bit in signature | Verify returns False | HIGH |

---

## 5. EDGE CASES

### 5.1. Edge Cases (4 tests)

| Test ID | Description | Input | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_RSA_EDGE_001 | Very small n (bits=16) | Sign with 16-bit keys | Works but insecure | MEDIUM |
| TC_RSA_EDGE_002 | Message boundary | Message length = 4k chars | Works correctly | LOW |
| TC_RSA_EDGE_003 | Empty after preprocessing | "123!@#" (no letters) | Empty or error | MEDIUM |
| TC_RSA_EDGE_004 | Maximum d value | d = n-1 | Should error (d > φ(n)) | LOW |

---

## 6. TEST EXECUTION PLAN

### 6.1. Execution Order
1. **Error Tests First** (fast, no computation)
2. **Basic Signing** (bits=32)
3. **Basic Verification** (bits=32)
4. **Integration Tests** (full cycles)
5. **Mathematical Properties**
6. **Edge Cases**

### 6.2. Timeout Handling
- Mark all potentially slow tests with `@pytest.mark.timeout(15)`
- Tests exceeding 15s will FAIL automatically
- Skip very small bits (2-7) that caused timeout in RSA crypto module

### 6.3. Expected Results
- **Total Tests**: ~53 tests
- **Expected Pass Rate**: 90-95%
- **Expected Timeouts**: 0-1 tests
- **Critical Tests**: All HIGH priority tests must pass

---

## 7. TEST COVERAGE

### 7.1. Coverage Target
- **Signing**: 100% code paths
- **Verification**: 100% code paths
- **Error Handling**: 100%
- **Integration**: 80%

### 7.2. Success Criteria
- All error handling tests pass
- Basic signing/verification works (bits=16,32,64)
- Sign-verify cycle works correctly
- Mathematical properties verified
- No unexpected crashes
- All HIGH priority tests pass

---

## 8. SKIPPED TESTS
### Tests NOT Implemented

| Category | Reason | Alternative |
|----------|--------|-------------|
| Very small bits (2-7) | Timeout from RSA crypto experience | Use bits 16+ only |
| Hash function signing | Implementation signs blocks, not hash | Test as-is |
| PKCS#1 padding | Not implemented in code | Test direct signing |
| Large bits (>64) | Timeout risk | Document performance separately |
