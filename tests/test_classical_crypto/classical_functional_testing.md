# FUNCTIONAL TESTING PLAN - CLASSICAL CRYPTOGRAPHY MODULE

## 1. CHỨC NĂNG 1: SHIFT CIPHER (CAESAR CIPHER)

### 1.1. Mã hóa Shift Cipher

#### TC_SHIFT_ENC_001: Mã hóa cơ bản với key dương
- **Mục tiêu**: Xác minh mã hóa đúng với key dương
- **Input**: message="HELLO", key=3
- **Expected**: `{"Encrypted": "KHOOR", "Key": 3}`
- **Priority**: High

#### TC_SHIFT_ENC_002: Mã hóa với key=0
- **Mục tiêu**: Xác minh không thay đổi khi key=0
- **Input**: message="HELLO", key=0
- **Expected**: `{"Encrypted": "HELLO", "Key": 0}`
- **Priority**: High

#### TC_SHIFT_ENC_003: Mã hóa với key=26
- **Mục tiêu**: Xác minh modulo 26 (26≡0)
- **Input**: message="HELLO", key=26
- **Expected**: `{"Encrypted": "HELLO", "Key": 26}`
- **Priority**: Medium

#### TC_SHIFT_ENC_004: Mã hóa với key âm
- **Mục tiêu**: Xác minh xử lý key âm
- **Input**: message="HELLO", key=-3
- **Expected**: Encrypted đúng (dịch ngược)
- **Priority**: Medium

#### TC_SHIFT_ENC_005: Mã hóa với ký tự đặc biệt
- **Mục tiêu**: Xác minh giữ nguyên ký tự không phải chữ
- **Input**: message="HELLO WORLD!", key=3
- **Expected**: Dấu cách và ! không thay đổi
- **Priority**: High

#### TC_SHIFT_ENC_006: Mã hóa chuỗi rỗng
- **Mục tiêu**: Xác minh xử lý chuỗi rỗng
- **Input**: message="", key=3
- **Expected**: `{"Encrypted": "", "Key": 3}`
- **Priority**: Low

#### TC_SHIFT_ENC_E001: Error - message null
- **Mục tiêu**: Xác minh error handling
- **Input**: message=None, key=3
- **Expected**: `{"Error": "NULL Value"}`
- **Priority**: High

#### TC_SHIFT_ENC_E002: Error - key null
- **Mục tiêu**: Xác minh error handling
- **Input**: message="HELLO", key=None
- **Expected**: `{"Error": "NULL Value"}`
- **Priority**: High

#### TC_SHIFT_ENC_E003: Error - key không phải số
- **Mục tiêu**: Xác minh validation key
- **Input**: message="HELLO", key="abc"
- **Expected**: `{"Error": "Key must be an integer"}`
- **Priority**: High

### 1.2. Giải mã Shift Cipher

#### TC_SHIFT_DEC_001: Giải mã cơ bản
- **Mục tiêu**: Xác minh giải mã đúng
- **Input**: encrypted="KHOOR", key=3
- **Expected**: `{"Decrypted": "HELLO"}`
- **Priority**: High

#### TC_SHIFT_DEC_002: Encrypt-Decrypt cycle
- **Mục tiêu**: Xác minh E(D(m))=m
- **Input**: Encrypt "HELLO" với key=5, sau đó decrypt
- **Expected**: Kết quả = "HELLO"
- **Priority**: High

#### TC_SHIFT_DEC_003: Giải mã với key sai
- **Mục tiêu**: Xác minh kết quả sai với key sai
- **Input**: encrypted="KHOOR", key=5 (sai, đúng là 3)
- **Expected**: Kết quả khác "HELLO"
- **Priority**: Medium

---

## 2. CHỨC NĂNG 2: AFFINE CIPHER

### 2.1. Mã hóa Affine Cipher

#### TC_AFFINE_ENC_001: Mã hóa cơ bản với a,b hợp lệ
- **Mục tiêu**: Xác minh mã hóa Affine đúng
- **Input**: message="AFFINE", a=5, b=8
- **Expected**: Encrypted đúng theo công thức
- **Priority**: High

#### TC_AFFINE_ENC_002: Mã hóa với a=1 (Shift Cipher)
- **Mục tiêu**: Xác minh a=1 thoái hóa về Shift
- **Input**: message="HELLO", a=1, b=3
- **Expected**: Giống Shift Cipher với key=3
- **Priority**: Medium

#### TC_AFFINE_ENC_003: Mã hóa với b=0
- **Mục tiêu**: Xác minh xử lý b=0
- **Input**: message="HELLO", a=5, b=0
- **Expected**: Mã hóa chỉ với nhân a
- **Priority**: Medium

#### TC_AFFINE_ENC_004: Mã hóa với ký tự đặc biệt
- **Mục tiêu**: Xác minh giữ nguyên ký tự không phải chữ
- **Input**: message="HELLO 123", a=5, b=8
- **Expected**: Dấu cách và số không đổi
- **Priority**: High

#### TC_AFFINE_ENC_E001: Error - a không nguyên tố cùng nhau với 26
- **Mục tiêu**: Xác minh validation GCD(a,26)=1
- **Input**: message="HELLO", a=2, b=8
- **Expected**: `{"Error": "a and 26 must be coprime"}`
- **Priority**: High

#### TC_AFFINE_ENC_E002: Error - a=0
- **Mục tiêu**: Xác minh validation a≠0
- **Input**: message="HELLO", a=0, b=8
- **Expected**: `{"Error": ...}`
- **Priority**: High

#### TC_AFFINE_ENC_E003: Error - message null
- **Mục tiêu**: Xác minh error handling
- **Input**: message=None, a=5, b=8
- **Expected**: `{"Error": "NULL Value"}`
- **Priority**: High

### 2.2. Giải mã Affine Cipher

#### TC_AFFINE_DEC_001: Giải mã cơ bản
- **Mục tiêu**: Xác minh giải mã đúng
- **Input**: encrypted=result_from_encrypt, a=5, b=8
- **Expected**: `{"Decrypted": "AFFINE"}`
- **Priority**: High

#### TC_AFFINE_DEC_002: Encrypt-Decrypt cycle
- **Mục tiêu**: Xác minh E(D(m))=m
- **Input**: Encrypt "AFFINE CIPHER" rồi decrypt
- **Expected**: Kết quả = "AFFINE CIPHER"
- **Priority**: High

#### TC_AFFINE_DEC_003: Tính nghịch đảo modular của a
- **Mục tiêu**: Xác minh tính đúng a_inv
- **Input**: a=5, m=26
- **Expected**: a_inv=21 (vì 5*21=105≡1 mod 26)
- **Priority**: Medium

---

## 3. CHỨC NĂNG 3: VIGENÈRE CIPHER

### 3.1. Mã hóa Vigenère Cipher

#### TC_VIGENERE_ENC_001: Mã hóa cơ bản
- **Mục tiêu**: Xác minh mã hóa Vigenère đúng
- **Input**: message="HELLO", key="KEY"
- **Expected**: Encrypted theo từ khóa lặp lại
- **Priority**: High

#### TC_VIGENERE_ENC_002: Key dài hơn message
- **Mục tiêu**: Xác minh xử lý key dài
- **Input**: message="HI", key="LEMON"
- **Expected**: Chỉ dùng "LE"
- **Priority**: Medium

#### TC_VIGENERE_ENC_003: Key ngắn hơn message
- **Mục tiêu**: Xác minh key lặp lại
- **Input**: message="HELLOWORLD", key="KEY"
- **Expected**: Key lặp: K-E-Y-K-E-Y-K-E-Y-K
- **Priority**: High

#### TC_VIGENERE_ENC_004: Key có chữ thường
- **Mục tiêu**: Xác minh tự động uppercase key
- **Input**: message="HELLO", key="key"
- **Expected**: Kết quả giống key="KEY"
- **Priority**: Medium

#### TC_VIGENERE_ENC_005: Message có chữ thường và HOA
- **Mục tiêu**: Xác minh giữ nguyên case
- **Input**: message="HeLLo", key="KEY"
- **Expected**: Case được bảo toàn
- **Priority**: High

#### TC_VIGENERE_ENC_006: Ký tự đặc biệt
- **Mục tiêu**: Xác minh giữ nguyên ký tự không phải chữ
- **Input**: message="HELLO WORLD!", key="KEY"
- **Expected**: Dấu cách và ! không đổi
- **Priority**: High

#### TC_VIGENERE_ENC_E001: Error - key rỗng
- **Mục tiêu**: Xác minh validation key
- **Input**: message="HELLO", key=""
- **Expected**: `{"Error": ...}`
- **Priority**: High

#### TC_VIGENERE_ENC_E002: Error - message null
- **Mục tiêu**: Xác minh error handling
- **Input**: message=None, key="KEY"
- **Expected**: `{"Error": "NULL Value"}`
- **Priority**: High

### 3.2. Giải mã Vigenère Cipher

#### TC_VIGENERE_DEC_001: Giải mã cơ bản
- **Mục tiêu**: Xác minh giải mã đúng
- **Input**: encrypted=result_from_encrypt, key="KEY"
- **Expected**: `{"Decrypted": "HELLO"}`
- **Priority**: High

#### TC_VIGENERE_DEC_002: Encrypt-Decrypt cycle
- **Mục tiêu**: Xác minh E(D(m))=m
- **Input**: Encrypt "VIGENERE CIPHER" rồi decrypt
- **Expected**: Kết quả = "VIGENERE CIPHER"
- **Priority**: High

---

## 4. CHỨC NĂNG 4: HILL CIPHER

### 4.1. Mã hóa Hill Cipher

#### TC_HILL_ENC_001: Mã hóa cơ bản 2x2
- **Mục tiêu**: Xác minh mã hóa Hill với ma trận 2x2
- **Input**: message="HILL", key="HI" (tạo ma trận 2x2)
- **Expected**: Encrypted đúng
- **Priority**: High

#### TC_HILL_ENC_002: Mã hóa 3x3
- **Mục tiêu**: Xác minh ma trận 3x3
- **Input**: message="HILLCIPHER", key="KEY" (ma trận 3x3)
- **Expected**: Encrypted đúng
- **Priority**: Medium

#### TC_HILL_ENC_003: Message length chia hết cho key length
- **Mục tiêu**: Xác minh không cần padding
- **Input**: message="ABCD", key="HI" (2x2)
- **Expected**: Mã hóa đầy đủ không padding
- **Priority**: Medium

#### TC_HILL_ENC_004: Message length không chia hết
- **Mục tiêu**: Xác minh padding/truncate
- **Input**: message="ABC", key="HI" (2x2)
- **Expected**: Xử lý padding hoặc bỏ qua
- **Priority**: High

#### TC_HILL_ENC_E001: Error - ma trận không khả nghịch
- **Mục tiêu**: Xác minh validation det(K)≠0
- **Input**: key tạo ma trận singular
- **Expected**: `{"Error": "Singular matrix"}`
- **Priority**: High

#### TC_HILL_ENC_E002: Error - message null
- **Mục tiêu**: Xác minh error handling
- **Input**: message=None, key="KEY"
- **Expected**: `{"Error": "NULL Value"}`
- **Priority**: High

### 4.2. Giải mã Hill Cipher

#### TC_HILL_DEC_001: Giải mã cơ bản
- **Mục tiêu**: Xác minh giải mã đúng
- **Input**: encrypted=result_from_encrypt, key="HI"
- **Expected**: `{"Decrypted": "HILL"}`
- **Priority**: High

#### TC_HILL_DEC_002: Encrypt-Decrypt cycle
- **Mục tiêu**: Xác minh E(D(m))=m
- **Input**: Encrypt rồi decrypt
- **Expected**: Kết quả = original message
- **Priority**: High

#### TC_HILL_DEC_003: Tính ma trận nghịch đảo
- **Mục tiêu**: Xác minh K^(-1) tính đúng
- **Input**: Ma trận key
- **Expected**: K * K^(-1) ≡ I (mod 26)
- **Priority**: Medium

---

## 5. INTEGRATION & CROSS-CIPHER TESTS

### 5.1. Integration Tests

#### TC_INTEG_001: So sánh Shift vs Affine (a=1)
- **Mục tiêu**: Xác minh Affine(a=1) = Shift
- **Input**: Same message, key_shift=b, affine(a=1,b=b)
- **Expected**: Kết quả giống nhau
- **Priority**: Medium

#### TC_INTEG_002: Vigenère với key 1 ký tự = Shift
- **Mục tiêu**: Xác minh Vigenère thoái hóa về Shift
- **Input**: Vigenère với key="C" (shift=2)
- **Expected**: Giống Shift với key=2
- **Priority**: Medium

#### TC_INTEG_003: Consistency check
- **Mục tiêu**: Tất cả cipher đều encrypt-decrypt đúng
- **Input**: Cùng message test cho tất cả
- **Expected**: Tất cả đều D(E(m))=m
- **Priority**: High

---

## 6. EDGE CASES & SECURITY

### 6.1. Edge Cases

#### TC_EDGE_001: Message rất dài
- **Mục tiêu**: Xác minh xử lý message lớn
- **Input**: 1000 ký tự
- **Expected**: Hoạt động bình thường
- **Priority**: Low

#### TC_EDGE_002: Key với giá trị biên
- **Mục tiêu**: Test boundary values
- **Input**: key=1, key=25 cho Shift
- **Expected**: Hoạt động đúng
- **Priority**: Medium

#### TC_EDGE_003: Tất cả chữ thường
- **Mục tiêu**: Xác minh case handling
- **Input**: message="hello world"
- **Expected**: Mã hóa đúng, giữ case
- **Priority**: Medium

#### TC_EDGE_004: Chỉ số và ký tự đặc biệt
- **Mục tiêu**: Xác minh không mã hóa
- **Input**: message="12345 !@#$%"
- **Expected**: Giữ nguyên
- **Priority**: Low

### 6.2. Security & Validation

#### TC_SEC_001: Brute force Shift Cipher
- **Mục tiêu**: Đánh giá độ yếu của Shift
- **Input**: Encrypted text
- **Expected**: Có thể crack với 26 thử
- **Priority**: Low (informational)

#### TC_SEC_002: Key strength validation
- **Mục tiêu**: Kiểm tra điều kiện key
- **Input**: Various invalid keys
- **Expected**: Reject invalid keys
- **Priority**: Medium