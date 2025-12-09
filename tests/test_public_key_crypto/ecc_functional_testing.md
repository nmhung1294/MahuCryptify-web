# ECC CRYPTOSYSTEM - FUNCTIONAL TEST PLAN
## 1. KEY GENERATION TESTS
### 1.1. Basic Key Generation (10 tests)

| Test ID | Description | Bits | Expected | Priority |
|---------|-------------|------|----------|----------|
| TC_ECC_KEY_001 | Generate with bits=10 | 10 | Success, returns (p,a,b,P,B,s) | HIGH |
| TC_ECC_KEY_002 | Generate with bits=12 | 12 | Success | HIGH |
| TC_ECC_KEY_003 | Generate with bits=15 | 15 | Success (may be slow) | MEDIUM |
| TC_ECC_KEY_004 | Verify p is prime | 10 | Miller-Rabin returns True | HIGH |
| TC_ECC_KEY_005 | Verify discriminant ≠ 0 | 10 | 4a³+27b² ≠ 0 (mod p) | HIGH |
| TC_ECC_KEY_006 | Verify P on curve | 10 | Py² ≡ Px³+aPx+b (mod p) | HIGH |
| TC_ECC_KEY_007 | Verify B on curve | 10 | By² ≡ Bx³+aBx+b (mod p) | HIGH |
| TC_ECC_KEY_008 | Verify B = s×P | 10 | double_and_add(P,s) == B | HIGH |
| TC_ECC_KEY_009 | Verify s in range | 10 | 1 < s < p-1 | MEDIUM |
| TC_ECC_KEY_010 | Key format validation | 10 | All fields present, correct types | HIGH |

### 1.2. Key Generation Error Tests (5 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_ECC_KEY_E001 | Null bits | bits=None | "NULL Value - Please enter bits" | HIGH |
| TC_ECC_KEY_E002 | String bits | bits="abc" | "Bits must be an integer" | HIGH |
| TC_ECC_KEY_E003 | Zero bits | bits=0 | "Bits must be greater than 0" | HIGH |
| TC_ECC_KEY_E004 | Negative bits | bits=-5 | "Bits must be greater than 0" | HIGH |
| TC_ECC_KEY_E005 | One bit | bits=1 | "Bits must be greater than 0" | MEDIUM |


---

## 2. ENCRYPTION TESTS

### 2.1. Basic Encryption (8 tests)

| Test ID | Description | Message | Bits | Expected | Priority |
|---------|-------------|---------|------|----------|----------|
| TC_ECC_ENC_001 | Encrypt "ABC" | "ABC" | 10 | Success, message points + encrypted | HIGH |
| TC_ECC_ENC_002 | Encrypt "TEST" | "TEST" | 10 | Success, 2 pairs (4 chars → 2 blocks) | HIGH |
| TC_ECC_ENC_003 | Encrypt single char | "A" | 10 | Success, 1 pair | MEDIUM |
| TC_ECC_ENC_004 | Encrypt with special chars | "ABC!@#" | 10 | Success, pre_solve removes special | MEDIUM |
| TC_ECC_ENC_005 | Encrypt lowercase | "abc" | 10 | Success, converts to uppercase | MEDIUM |
| TC_ECC_ENC_006 | Encrypt result format | "TEST" | 10 | Contains "Message points" and "Encrypted" | HIGH |
| TC_ECC_ENC_007 | Encrypt same message twice | "TEST" | 10 | Different k → same points, different cipher | HIGH |
| TC_ECC_ENC_008 | Encrypt long text | "HELLO" | 10 | Success, 2 blocks (5 chars → "HEL","LO") | MEDIUM |

### 2.2. Encryption Error Tests (8 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_ECC_ENC_E001 | Null message | message=None | "NULL Value" | HIGH |
| TC_ECC_ENC_E002 | Empty message | message="" | "NULL Value" | HIGH |
| TC_ECC_ENC_E003 | Null p | p=None | "NULL Value" | HIGH |
| TC_ECC_ENC_E004 | Null a | a=None | "NULL Value" | HIGH |
| TC_ECC_ENC_E005 | Null P | P=None | "NULL Value" | HIGH |
| TC_ECC_ENC_E006 | Null B | B=None | "NULL Value" | HIGH |
| TC_ECC_ENC_E007 | p not prime | p=100 | "p is not prime" | HIGH |
| TC_ECC_ENC_E008 | Invalid point format | P="invalid" | Error (type conversion) | MEDIUM |

## 3. DECRYPTION TESTS

### 3.1. Basic Decryption (6 tests)

| Test ID | Description | Setup | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_ECC_DEC_001 | Decrypt basic | Encrypt "TEST" → Decrypt | Points match message_points | HIGH |
| TC_ECC_DEC_002 | Decrypt single block | Encrypt "ABC" → Decrypt | Correct point | HIGH |
| TC_ECC_DEC_003 | Decrypt with correct keys | Full cycle | Points == original message_points | HIGH |
| TC_ECC_DEC_004 | Decrypt format validation | Decrypt | Returns {"Decrypted": "[...]"} | HIGH |
| TC_ECC_DEC_005 | Decrypt multiple blocks | Encrypt "HELLO" → Decrypt | All points correct | MEDIUM |
| TC_ECC_DEC_006 | Decrypt with wrong keys | Wrong s | Points != message_points | MEDIUM |


### 3.2. Decryption Error Tests (7 tests)

| Test ID | Description | Input | Expected Error | Priority |
|---------|-------------|-------|----------------|----------|
| TC_ECC_DEC_E001 | Null encrypted | encrypted=None | "NULL Value" | HIGH |
| TC_ECC_DEC_E002 | Empty encrypted | encrypted="" | "NULL Value" | HIGH |
| TC_ECC_DEC_E003 | Null p | p=None | "NULL Value" | HIGH |
| TC_ECC_DEC_E004 | Null a | a=None | "NULL Value" | HIGH |
| TC_ECC_DEC_E005 | Null s | s=None | "NULL Value" | HIGH |
| TC_ECC_DEC_E006 | p not prime | p=100 | "p is not prime" | HIGH |
| TC_ECC_DEC_E007 | Invalid format | encrypted="invalid" | Parse error | MEDIUM |

## 4. INTEGRATION TESTS

### 4.1. Full Cycle Tests (5 tests)

| Test ID | Description | Flow | Bits | Expected | Priority |
|---------|-------------|------|------|----------|----------|
| TC_ECC_INT_001 | Full cycle Gen→Enc→Dec | Generate → Encrypt "TEST" → Decrypt | 10 | Points match | HIGH |
| TC_ECC_INT_002 | Cycle with bits=12 | Generate(12) → Encrypt "AB" → Decrypt | 12 | Points match | MEDIUM |
| TC_ECC_INT_003 | Cycle single char | Generate(10) → Encrypt "X" → Decrypt | 10 | Correct point | MEDIUM |
| TC_ECC_INT_004 | Multiple messages same keys | Gen → Enc "A", "B", "C" → Dec all | 10 | All decrypt correctly | LOW |
| TC_ECC_INT_005 | Different keys independence | Gen 2 key pairs → Cross-test | 10 | Wrong keys fail | LOW |

---

## 5. EDGE CASES & SECURITY

### 5.1. Edge Cases (4 tests)

| Test ID | Description | Input | Expected | Priority |
|---------|-------------|-------|----------|----------|
| TC_ECC_EDGE_001 | Very small p (bits=10) | bits=10 | Works but insecure | MEDIUM |
| TC_ECC_EDGE_002 | Message with spaces | "HE LLO" | Spaces removed/handled | LOW |
| TC_ECC_EDGE_003 | Low entropy message | "AAA" | Works | LOW |
| TC_ECC_EDGE_004 | Boundary s value | s near p-1 | Works | LOW |


### 5.2. Mathematical Properties (5 tests)

| Test ID | Description | Test | Expected | Priority |
|---------|-------------|------|----------|----------|
| TC_ECC_MATH_001 | P on curve formula | Py²≡Px³+aPx+b (mod p) | True | HIGH |
| TC_ECC_MATH_002 | B on curve formula | By²≡Bx³+aBx+b (mod p) | True | HIGH |
| TC_ECC_MATH_003 | B = s×P formula | double_and_add(P,s)==B | True | HIGH |
| TC_ECC_MATH_004 | Discriminant formula | Δ=-16(4a³+27b²)≠0 | True | MEDIUM |
| TC_ECC_MATH_005 | M = C₂ - sC₁ formula | Decrypt matches encryption | True | HIGH |


## 6. SKIPPED TESTS (Due to Timeout Risk)

### Tests NOT Implemented

| Category | Reason | Alternative |
|----------|--------|-------------|
| Bits > 15 | Timeout >20s for curve order calculation | Use bits 10-15 only |
| Extensive integration | Too slow with multiple full cycles | Limit to 5 integration tests |
| Large message encryption | Many blocks → slow double_and_add | Test with ≤5 chars |
| Performance benchmarks | Not functional testing focus | Document in report instead |
| Standard curves (secp256r1) | Not implemented in code | Test random curves only |


