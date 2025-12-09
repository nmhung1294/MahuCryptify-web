# RSA CRYPTOSYSTEM - FUNCTIONAL TESTING PLAN

## 1. RSA KEY GENERATION TESTS

### Test Cases: Sinh khóa RSA

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_KEY_001 | High | Sinh khóa với bits=8 (minimal) | Success: keys generated |
| TC_RSA_KEY_002 | High | Sinh khóa với bits=64 | Success: keys generated |
| TC_RSA_KEY_003 | High | Sinh khóa với bits=128 | Success: keys generated |
| TC_RSA_KEY_004 | Medium | Sinh khóa với bits=256 | Success: keys generated |
| TC_RSA_KEY_005 | Medium | Sinh khóa với bits=512 | Success: keys generated |
| TC_RSA_KEY_006 | Low | Sinh khóa với bits=1024 | Success (may be slow) |
| TC_RSA_KEY_007 | High | Verify n = p * q | Assert n == p * q |
| TC_RSA_KEY_008 | High | Verify e and φ(n) coprime | Assert GCD(e, φ(n)) = 1 |
| TC_RSA_KEY_009 | High | Verify d is modular inverse | Assert (e*d) % φ(n) = 1 |
| TC_RSA_KEY_010 | High | Verify p and q are primes | Miller-Rabin test passes |
| TC_RSA_KEY_011 | Medium | Verify p ≠ q | Assert p != q |
| TC_RSA_KEY_012 | Medium | Key format validation | Check all keys present |
| TC_RSA_KEY_013 | Low | Multiple key generation | Different keys each time |

### Error Test Cases: Key Generation

| Test ID | Priority | Test Case | Expected Error |
|---------|----------|-----------|----------------|
| TC_RSA_KEY_E001 | High | bits = null | "NULL Value - Please enter bits" |
| TC_RSA_KEY_E002 | High | bits = "abc" | "Bits must be an integer" |
| TC_RSA_KEY_E003 | High | bits = 0 | "Bits must be greater than 0" |
| TC_RSA_KEY_E004 | High | bits = 1 | "Bits must be greater than 0" |
| TC_RSA_KEY_E005 | High | bits = -5 | "Bits must be greater than 0" |
| TC_RSA_KEY_E006 | Medium | bits = None | "NULL Value - Please enter bits" |

**Total Key Generation Tests: 19**

---

## 2. RSA ENCRYPTION TESTS

### Test Cases: Mã hóa RSA

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_ENC_001 | High | Encrypt "HELLO" | Success: returns encrypted list |
| TC_RSA_ENC_002 | High | Encrypt "A" | Success: single character |
| TC_RSA_ENC_003 | High | Encrypt "ABCD" | Success: exactly 4 chars (1 block) |
| TC_RSA_ENC_004 | Medium | Encrypt "HELLOWORLDTEST" | Success: multiple blocks |
| TC_RSA_ENC_005 | Medium | Encrypt long text (100 chars) | Success: many blocks |
| TC_RSA_ENC_006 | Medium | Encrypt with e=3 | Success: fast encryption |
| TC_RSA_ENC_007 | Medium | Encrypt with e=65537 | Success: common exponent |
| TC_RSA_ENC_008 | Low | Encrypt with special chars | Success: chars removed |
| TC_RSA_ENC_009 | Low | Encrypt with numbers | Success: numbers removed |
| TC_RSA_ENC_010 | Low | Encrypt lowercase | Success: converted to upper |
| TC_RSA_ENC_011 | Medium | Encrypt with small n | Success: M mod n |
| TC_RSA_ENC_012 | High | Verify format | Returns {"Encrypted": "[...]"} |

### Error Test Cases: Encryption

| Test ID | Priority | Test Case | Expected Error |
|---------|----------|-----------|----------------|
| TC_RSA_ENC_E001 | High | message = null | "NULL Value" |
| TC_RSA_ENC_E002 | High | message = "" | "NULL Value" |
| TC_RSA_ENC_E003 | High | n = null | "NULL Value" |
| TC_RSA_ENC_E004 | High | e = null | "NULL Value" |
| TC_RSA_ENC_E005 | High | n = "abc" | "n and e must be integers" |
| TC_RSA_ENC_E006 | High | e = "xyz" | "n and e must be integers" |
| TC_RSA_ENC_E007 | High | n = 0 | "NULL Value" |
| TC_RSA_ENC_E008 | High | e = 0 | "NULL Value" |
| TC_RSA_ENC_E009 | High | n = -5 | "NULL Value" |
| TC_RSA_ENC_E010 | Medium | e > n | "NULL Value" |

**Total Encryption Tests: 22**

---

## 3. RSA DECRYPTION TESTS

### Test Cases: Giải mã RSA

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_DEC_001 | High | Decrypt basic ciphertext | Success: returns original |
| TC_RSA_DEC_002 | High | Decrypt single block | Success: short message |
| TC_RSA_DEC_003 | High | Decrypt multiple blocks | Success: long message |
| TC_RSA_DEC_004 | High | Decrypt with correct keys | D(C) = M |
| TC_RSA_DEC_005 | Medium | Decrypt with p, q, d | Success: uses all params |
| TC_RSA_DEC_006 | High | Verify n = p * q in decrypt | Internal calculation |
| TC_RSA_DEC_007 | Medium | Decrypt empty ciphertext | Appropriate handling |

### Error Test Cases: Decryption

| Test ID | Priority | Test Case | Expected Error |
|---------|----------|-----------|----------------|
| TC_RSA_DEC_E001 | High | encrypted = null | "NULL Value" |
| TC_RSA_DEC_E002 | High | encrypted = "" | "NULL Value" |
| TC_RSA_DEC_E003 | High | p = null | "NULL Value" |
| TC_RSA_DEC_E004 | High | q = null | "NULL Value" |
| TC_RSA_DEC_E005 | High | d = null | "NULL Value" |
| TC_RSA_DEC_E006 | High | p = "abc" | "p, q, d must be integers" |
| TC_RSA_DEC_E007 | High | p = 0 | "NULL Value" |
| TC_RSA_DEC_E008 | High | q = 0 | "NULL Value" |
| TC_RSA_DEC_E009 | High | d = 0 | "NULL Value" |
| TC_RSA_DEC_E010 | Medium | d > n | "Invalid d" |
| TC_RSA_DEC_E011 | Medium | p not prime | "p or q is not prime" |
| TC_RSA_DEC_E012 | Medium | q not prime | "p or q is not prime" |
| TC_RSA_DEC_E013 | Medium | Wrong keys (p,q,d) | Incorrect decryption |

**Total Decryption Tests: 20**

---

## 4. INTEGRATION & CYCLE TESTS

### Test Cases: Encrypt-Decrypt Integration

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_INT_001 | High | Full cycle: Gen→Enc→Dec | D(E(m)) = m |
| TC_RSA_INT_002 | High | Cycle with bits=64 | Success |
| TC_RSA_INT_003 | High | Cycle with bits=128 | Success |
| TC_RSA_INT_004 | Medium | Cycle with long message | Success |
| TC_RSA_INT_005 | Medium | Cycle with single char | Success |
| TC_RSA_INT_006 | Medium | Multiple messages same keys | All decrypt correctly |
| TC_RSA_INT_007 | High | Decrypt with wrong keys | Incorrect result |
| TC_RSA_INT_008 | Medium | Different keys each gen | Keys independent |

**Total Integration Tests: 8**

---

## 5. EDGE CASES & SECURITY TESTS

### Test Cases: Edge Cases

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_EDGE_001 | Medium | Very small bits (2-7) | May fail or succeed |
| TC_RSA_EDGE_002 | Medium | Message = "Z" * 100 | Success: long uniform |
| TC_RSA_EDGE_003 | Low | Message all A's | Success: low entropy |
| TC_RSA_EDGE_004 | Medium | Keys at boundary (min bits) | Success |
| TC_RSA_EDGE_005 | Low | Unicode in message | Removed/handled |
| TC_RSA_EDGE_006 | Medium | Very long message (1000 chars) | Success: many blocks |
| TC_RSA_EDGE_007 | Medium | Message with spaces | Spaces removed |
| TC_RSA_EDGE_008 | Low | Mixed case message | Converted to upper |

### Test Cases: Security Properties

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_SEC_001 | High | p and q must be prime | Miller-Rabin confirms |
| TC_RSA_SEC_002 | High | p ≠ q always | Never equal |
| TC_RSA_SEC_003 | High | GCD(e, φ(n)) = 1 | Always coprime |
| TC_RSA_SEC_004 | High | 1 < e < φ(n) | Range check |
| TC_RSA_SEC_005 | Medium | (e * d) mod φ(n) = 1 | Modular inverse |
| TC_RSA_SEC_006 | Medium | Keys are deterministic | Same seed → same keys? |

**Total Edge/Security Tests: 14**

---

## 6. MATHEMATICAL CORRECTNESS TESTS

### Test Cases: Mathematical Properties

| Test ID | Priority | Test Case | Expected Result |
|---------|----------|-----------|-----------------|
| TC_RSA_MATH_001 | High | n = p * q | Exact equality |
| TC_RSA_MATH_002 | High | φ(n) = (p-1)(q-1) | Euler's totient |
| TC_RSA_MATH_003 | High | e * d ≡ 1 (mod φ(n)) | Inverse property |
| TC_RSA_MATH_004 | High | M^(e*d) ≡ M (mod n) | RSA property |
| TC_RSA_MATH_005 | Medium | C^d ≡ M (mod n) | Decryption formula |
| TC_RSA_MATH_006 | Medium | C = M^e mod n | Encryption formula |
| TC_RSA_MATH_007 | Low | Verify modular exp | Correctness |

**Total Math Tests: 7**