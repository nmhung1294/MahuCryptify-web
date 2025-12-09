# ELGAMAL CRYPTOSYSTEM MODULE - FUNCTIONAL TESTING PLAN

## 1. KEY GENERATION TESTS

### 1.1 Basic Key Generation

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_KEY_001 | Sinh khóa 16-bit | bits=16 | public_key: {p, alpha, beta}, private_key: a | High |
| TC_ELG_KEY_002 | Sinh khóa 32-bit | bits=32 | public_key: {p, alpha, beta}, private_key: a | High |
| TC_ELG_KEY_003 | Sinh khóa 64-bit | bits=64 | public_key: {p, alpha, beta}, private_key: a | Medium |

### 1.2 Mathematical Properties

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_KEY_004 | Verify p là số nguyên tố | bits=32 | miller_rabin_test(p) = True | High |
| TC_ELG_KEY_005 | Verify beta = alpha^a mod p | bits=32 | beta == pow(alpha, a, p) | High |
| TC_ELG_KEY_006 | Verify 1 < a < p-1 | bits=32 | 1 < a < p-1 | High |
| TC_ELG_KEY_007 | Verify alpha > 0 | bits=32 | alpha > 0 | Medium |
| TC_ELG_KEY_008 | Key format validation | bits=32 | Tất cả keys là string | Medium |
| TC_ELG_KEY_009 | Uniqueness test | bits=32 (2 lần) | p1 != p2 (high probability) | Medium |

### 1.3 Error Handling

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_KEY_E001 | Error: bits = null | bits=None | {"Error": "NULL Value"} | High |
| TC_ELG_KEY_E002 | Error: bits = 'abc' | bits='abc' | {"Error": "...integer..."} | High |
| TC_ELG_KEY_E003 | Error: bits = 0 | bits=0 | {"Error": "...greater than 0..."} | High |
| TC_ELG_KEY_E004 | Error: bits = 1 | bits=1 | {"Error": "...greater than 0..."} | Medium |
| TC_ELG_KEY_E005 | Error: bits = -5 | bits=-5 | {"Error": "...greater than 0..."} | Medium |

**Total Key Generation Tests:** ~14 tests

---

## 2. ENCRYPTION TESTS

### 2.1 Basic Encryption

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_ENC_001 | Encrypt 'HELLO' | message='HELLO', keys | {"Encrypted": "[[y1,y2],...]"} | High |
| TC_ELG_ENC_002 | Encrypt 'A' | message='A', keys | {"Encrypted": list} | High |
| TC_ELG_ENC_003 | Encrypt 'ABCD' | message='ABCD', keys | {"Encrypted": list} | Medium |
| TC_ELG_ENC_004 | Multiple blocks | message='HELLOWORLD' | {"Encrypted": multiple pairs} | Medium |
| TC_ELG_ENC_005 | Long text | message='A'*40 | {"Encrypted": many blocks} | Medium |

### 2.2 Text Processing

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_ENC_006 | Special chars | message='HELLO!@#' | Special chars removed | Medium |
| TC_ELG_ENC_007 | With numbers | message='HELLO123' | Numbers removed | Medium |
| TC_ELG_ENC_008 | Lowercase | message='hello' | Converted to uppercase | Medium |
| TC_ELG_ENC_009 | Mixed case | message='HeLLo' | Converted to uppercase | Medium |

### 2.3 Probabilistic Property

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_ENC_010 | Same message twice | 'TEST' (2 lần) | Different ciphertext (random k) | High |
| TC_ELG_ENC_011 | Result format | any message | String list format [[y1,y2],...] | Medium |

### 2.4 Error Handling

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_ENC_E001 | Error: message = null | message=None | {"Error": "NULL Value"} | High |
| TC_ELG_ENC_E002 | Error: message = '' | message='' | {"Error": "NULL Value"} | High |
| TC_ELG_ENC_E003 | Error: p = null | p=None | {"Error": "NULL Value"} | High |
| TC_ELG_ENC_E004 | Error: alpha = null | alpha=None | {"Error": "NULL Value"} | High |
| TC_ELG_ENC_E005 | Error: beta = null | beta=None | {"Error": "NULL Value"} | High |
| TC_ELG_ENC_E006 | Error: p = 'abc' | p='abc' | {"Error": "...integer..."} | High |
| TC_ELG_ENC_E007 | Error: p = 0 | p=0 | {"Error": "NULL Value"} | Medium |
| TC_ELG_ENC_E008 | Error: p not prime | p=100 | {"Error": "...not prime..."} | High |

**Total Encryption Tests:** ~19 tests

---

## 3. DECRYPTION TESTS

### 3.1 Basic Decryption

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_DEC_001 | Decrypt basic | encrypted='[[y1,y2]]', p, a | {"Decrypted": "HELLO"} | High |
| TC_ELG_DEC_002 | Single block | encrypted single pair | {"Decrypted": text} | High |
| TC_ELG_DEC_003 | Multiple blocks | encrypted multiple pairs | {"Decrypted": original} | High |
| TC_ELG_DEC_004 | Correct keys | Decrypt with matching keys | Original message | High |
| TC_ELG_DEC_005 | Uses p and a | Verify formula M = y2*(y1^(p-1-a)) mod p | Correct decryption | Medium |

### 3.2 Error Handling

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_DEC_E001 | Error: encrypted = null | encrypted=None | {"Error": "NULL Value"} | High |
| TC_ELG_DEC_E002 | Error: encrypted = '' | encrypted='' | {"Error": "NULL Value"} | High |
| TC_ELG_DEC_E003 | Error: p = null | p=None | {"Error": "NULL Value"} | High |
| TC_ELG_DEC_E004 | Error: a = null | a=None | {"Error": "NULL Value"} | High |
| TC_ELG_DEC_E005 | Error: p = 'abc' | p='abc' | {"Error": "...integer..."} | High |
| TC_ELG_DEC_E006 | Error: p = 0 | p=0 | {"Error": "NULL Value"} | Medium |
| TC_ELG_DEC_E007 | Error: a = 0 | a=0 | {"Error": "NULL Value"} | Medium |
| TC_ELG_DEC_E008 | Error: p not prime | p=100 | {"Error": "...not prime..."} | High |
| TC_ELG_DEC_E009 | Wrong keys | Decrypt với a khác | Incorrect result or error | Medium |

**Total Decryption Tests:** ~14 tests

---

## 4. INTEGRATION TESTS

### 4.1 Full Cycle Tests

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_INT_001 | Full cycle Gen→Enc→Dec | bits=32, message='HELLO' | Decrypted = 'HELLO' | High |
| TC_ELG_INT_002 | Cycle với 16-bit | bits=16, message='TEST' | Decrypted = 'TEST' | High |
| TC_ELG_INT_003 | Cycle với 64-bit | bits=64, message='HELLO' | Decrypted = 'HELLO' | Medium |
| TC_ELG_INT_004 | Long message cycle | bits=32, message='A'*32 | Decrypted = original | Medium |
| TC_ELG_INT_005 | Single char cycle | bits=32, message='X' | Decrypted = 'X' | Medium |
| TC_ELG_INT_006 | Multiple messages | Same keys, 3 messages | All decrypt correctly | High |

### 4.2 Probabilistic Property

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_INT_007 | Encrypt twice, decrypt both | 'TEST' (2 lần encrypt) | Both decrypt to 'TEST' | High |
| TC_ELG_INT_008 | Different keys independence | 2 key pairs | Encrypted with key1 != encrypted with key2 | Medium |

**Total Integration Tests:** ~8 tests

---

## 5. EDGE CASES & SECURITY

### 5.1 Edge Cases

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_EDGE_001 | Very long message | message='A'*100 | Encrypt/decrypt success | Medium |
| TC_ELG_EDGE_002 | Low entropy | message='A'*20 | Handles correctly | Low |
| TC_ELG_EDGE_003 | Message with spaces | message='HELLO WORLD' | Spaces handled | Medium |

### 5.2 Security Properties

| Test ID | Test Case | Input | Expected Output | Priority |
|---------|-----------|-------|-----------------|----------|
| TC_ELG_SEC_001 | p là số nguyên tố | Generated keys | miller_rabin_test(p) = True | High |
| TC_ELG_SEC_002 | 1 < a < p-1 | Generated keys | Range check passes | High |
| TC_ELG_SEC_003 | beta = alpha^a mod p | Generated keys | Formula verified | High |
| TC_ELG_SEC_004 | Different k each time | Encrypt same message | Different y1 values | High |

**Total Edge/Security Tests:** ~7 tests

---

## 6. MATHEMATICAL CORRECTNESS

### 6.1 Encryption Formula

| Test ID | Test Case | Formula | Expected | Priority |
|---------|-----------|---------|----------|----------|
| TC_ELG_MATH_001 | y1 = alpha^k mod p | Verify calculation | Correct y1 | High |
| TC_ELG_MATH_002 | y2 = M × beta^k mod p | Verify calculation | Correct y2 | High |

### 6.2 Decryption Formula

| Test ID | Test Case | Formula | Expected | Priority |
|---------|-----------|---------|----------|----------|
| TC_ELG_MATH_003 | M = y2 × (y1^(p-1-a)) mod p | Verify calculation | Original M | High |
| TC_ELG_MATH_004 | Fermat's Little Theorem | y1^(p-1) ≡ 1 (mod p) | Verified | Medium |

**Total Math Tests:** ~4 tests