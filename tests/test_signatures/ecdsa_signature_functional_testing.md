# ECDSA DIGITAL SIGNATURE - FUNCTIONAL TEST PLAN

### 1. Basic ECDSA Signing Tests (10 tests)
**Objective**: Verify basic signing functionality

#### TC_ECDSA_SIG_001: Sign 'HELLO' with 32 bits
- **Input**: message="HELLO", 32-bit ECC keys
- **Expected**: Success, returns signature and hash
- **Validation**: "Signed Message" and "Hashed Message" present

#### TC_ECDSA_SIG_002: Sign 'TEST' (1 block, 4 chars)
- **Input**: message="TEST", 32-bit keys
- **Expected**: Success, 1 signature tuple (r, s)
- **Validation**: Count tuples in result

#### TC_ECDSA_SIG_003: Sign single character 'A'
- **Input**: message="A", 32-bit keys
- **Expected**: Success, 1 signature tuple
- **Validation**: No error, signature present

#### TC_ECDSA_SIG_004: Sign 'HELLOWORLD' (multiple blocks)
- **Input**: message="HELLOWORLD" (10 chars = 3 blocks), 32-bit keys
- **Expected**: Success, 3 signature tuples
- **Validation**: Count tuples = 3

#### TC_ECDSA_SIG_005: Sign long text (20 'A's)
- **Input**: message="AAAAAAAAAAAAAAAAAAAA", 32-bit keys
- **Expected**: Success, 5 signature tuples (20 chars / 4)
- **Validation**: Count tuples = 5

#### TC_ECDSA_SIG_006: Sign with 16 bits (fast)
- **Input**: message="TEST", 16-bit keys
- **Expected**: Success, fast execution
- **Validation**: No error, signature present

#### TC_ECDSA_SIG_007: Sign with 64 bits (may be slower)
- **Input**: message="TEST", 64-bit keys
- **Expected**: Success, may take longer
- **Validation**: No error, signature present

#### TC_ECDSA_SIG_008: Check result format contains tuples
- **Input**: message="TEST", 32-bit keys
- **Expected**: Result has "Signed Message" with (r, s) tuples
- **Validation**: Check dict structure, tuple format

#### TC_ECDSA_SIG_009: Sign with special characters (removed by pre_solve)
- **Input**: message="TEST!@#", 32-bit keys
- **Expected**: Success, special chars removed
- **Validation**: No error, only "TEST" processed

#### TC_ECDSA_SIG_010: Sign lowercase (converted to uppercase)
- **Input**: message="test", 32-bit keys
- **Expected**: Success, converted to "TEST"
- **Validation**: No error

---

### 2. Text Processing Tests (4 tests)
**Objective**: Verify text preprocessing behavior

#### TC_ECDSA_SIG_T001: Special characters are removed
- **Input**: "HELLO" vs "HELLO!@#$"
- **Expected**: Same hash (special chars removed)
- **Validation**: Compare hashed messages

#### TC_ECDSA_SIG_T002: Numbers are removed
- **Input**: "TEST" vs "TEST123"
- **Expected**: Same hash (numbers removed)
- **Note**: May fail if BUG-RSA-SIG-001 exists in ECDSA
- **Validation**: Compare hashed messages

#### TC_ECDSA_SIG_T003: Spaces are handled
- **Input**: "HELLO WORLD"
- **Expected**: Success, spaces removed/handled
- **Validation**: No error

#### TC_ECDSA_SIG_T004: Mixed case converted to uppercase
- **Input**: "HELLO" vs "HeLLo"
- **Expected**: Same hash (case normalized)
- **Validation**: Compare hashed messages

---

### 3. Error Handling Tests (13 tests)
**Objective**: Verify proper error handling for invalid inputs

#### TC_ECDSA_SIG_E001: Null message
- **Input**: message=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E002: Empty message
- **Input**: message=""
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E003: Null p
- **Input**: p=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E004: Null q
- **Input**: q=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E005: Null a
- **Input**: a=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E006: Null G
- **Input**: G=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E007: Null d
- **Input**: d=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E008: p not prime
- **Input**: p=100 (not prime)
- **Expected**: Error "p or q is not prime"

#### TC_ECDSA_SIG_E009: q not prime
- **Input**: q=100 (not prime)
- **Expected**: Error "p or q is not prime"

#### TC_ECDSA_SIG_E010: G not on curve
- **Input**: G=(1000, 1000) (invalid point)
- **Expected**: Error "G is not on the curve"

#### TC_ECDSA_SIG_E011: p = 0
- **Input**: p=0
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E012: q = 0
- **Input**: q=0
- **Expected**: Error "Enter Again"

#### TC_ECDSA_SIG_E013: d = 0
- **Input**: d=0
- **Expected**: Error "Enter Again"

---

### 4. Basic Verification Tests (8 tests)
**Objective**: Verify signature verification functionality

#### TC_ECDSA_VER_001: Verify valid signature
- **Input**: Sign "TEST", then verify with correct keys
- **Expected**: Verification = True
- **Validation**: Check "Verification: " = "True"

#### TC_ECDSA_VER_002: Verify signature of multiple blocks
- **Input**: Sign "HELLO" (2 blocks), verify
- **Expected**: Verification = True

#### TC_ECDSA_VER_003: Verify with matching keys
- **Input**: Sign and verify with same key pair
- **Expected**: Verification = True

#### TC_ECDSA_VER_004: Verify single block signature
- **Input**: Sign "TEST" (1 block), verify
- **Expected**: Verification = True

#### TC_ECDSA_VER_005: Verify long message signature
- **Input**: Sign 20 'A's, verify
- **Expected**: Verification = True

#### TC_ECDSA_VER_006: Verify with modified signature
- **Input**: Sign "TEST", modify r value, verify
- **Expected**: Verification = False

#### TC_ECDSA_VER_007: Verify with different hash
- **Input**: Sign "TEST", use hash from "HELLO"
- **Expected**: Verification = False

#### TC_ECDSA_VER_008: Verify with different keys
- **Input**: Sign with keys1, verify with keys2
- **Expected**: Verification = False

---

### 5. Verification Error Handling Tests (7 tests)
**Objective**: Verify error handling in verification

#### TC_ECDSA_VER_E001: Null hash
- **Input**: hash_message=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E002: Empty hash
- **Input**: hash_message=""
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E003: Null signature
- **Input**: signed_message=None
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E004: Null p
- **Input**: p=None in verification
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E005: Null q
- **Input**: q=None in verification
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E006: Null G
- **Input**: G=None in verification
- **Expected**: Error "Enter Again"

#### TC_ECDSA_VER_E007: Null Q
- **Input**: Q=None (public key)
- **Expected**: Error "Enter Again"

---

### 6. Integration Tests (6 tests)
**Objective**: Test full sign-verify cycle

#### TC_ECDSA_INT_001: Full cycle with 32 bits
- **Input**: Sign and verify "TEST" with 32-bit keys
- **Expected**: Verification = True

#### TC_ECDSA_INT_002: Full cycle with 16 bits
- **Input**: Sign and verify "TEST" with 16-bit keys
- **Expected**: Verification = True

#### TC_ECDSA_INT_003: Full cycle with 64 bits
- **Input**: Sign and verify "TEST" with 64-bit keys
- **Expected**: Verification = True

#### TC_ECDSA_INT_004: Multiple messages
- **Input**: Sign and verify ["TEST", "HELLO", "WORLD"]
- **Expected**: All verifications = True

#### TC_ECDSA_INT_005: Sign twice probabilistic
- **Input**: Sign "TEST" twice with same keys
- **Expected**: Different signatures (due to random k)
- **Note**: Signatures may differ if k is truly random

#### TC_ECDSA_INT_006: Cross-key verification
- **Input**: Sign with keys1, verify with keys2
- **Expected**: Verification = False

---

### 7. Mathematical Property Tests (6 tests)
**Objective**: Verify ECDSA mathematical correctness

#### TC_ECDSA_MATH_001: r is x-coordinate mod q
- **Input**: Sign "TEST", extract r values
- **Expected**: r = (k×G).x mod q
- **Validation**: Check r range [1, q-1]

#### TC_ECDSA_MATH_002: Verification formula
- **Input**: Sign and verify "TEST"
- **Expected**: P = u1×G + u2×Q, P.x mod q == r
- **Validation**: verify_ECDSA returns True

#### TC_ECDSA_MATH_003: Signature format
- **Input**: Sign "HELLO"
- **Expected**: List of (r, s) tuples
- **Validation**: Each signature is 2-tuple of integers

#### TC_ECDSA_MATH_004: Invalid signature detection
- **Input**: Sign, modify r, verify
- **Expected**: Verification = False

#### TC_ECDSA_MATH_005: Different k per block
- **Input**: Sign "HELLOWORLD" (multiple blocks)
- **Expected**: Different (r, s) for each block
- **Note**: Implementation generates new k per block

#### TC_ECDSA_MATH_006: Point operations
- **Input**: Sign "TEST", check Q on curve
- **Expected**: Q = d×G is valid point on curve

---

### 8. Edge Case Tests (5 tests)
**Objective**: Test boundary conditions

#### TC_ECDSA_EDGE_001: Very small p (16 bits)
- **Input**: 16-bit ECC keys
- **Expected**: Success (though insecure)

#### TC_ECDSA_EDGE_002: Message boundary (4k chars)
- **Input**: 8 chars (2 blocks)
- **Expected**: Success, 2 signature tuples

#### TC_ECDSA_EDGE_003: Empty after preprocessing
- **Input**: "123!@#" (no letters)
- **Expected**: May error or empty result, no crash

#### TC_ECDSA_EDGE_004: Curve parameter validation
- **Input**: Valid ECC curve parameters
- **Expected**: G and Q on curve confirmed

#### TC_ECDSA_EDGE_005: Large d value
- **Input**: d = q - 2 (large but valid)
- **Expected**: Success, d < q is valid