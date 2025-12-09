# FUNCTIONAL TESTING PLAN - ALGORITHM MODULE

## 1. CHỨC NĂNG 1: KIỂM TRA SỐ NGUYÊN TỐ (AKS)

### 1.1. Test Cases - Dữ liệu hợp lệ

#### TC_AKS_001: Kiểm tra số nguyên tố nhỏ
- **Mục tiêu**: Xác minh AKS nhận diện đúng số nguyên tố nhỏ
- **Input**: n = 7
- **Expected Output**: `{"": "7 - Prime"}`
- **Priority**: High

#### TC_AKS_002: Kiểm tra hợp số nhỏ
- **Mục tiêu**: Xác minh AKS nhận diện đúng hợp số nhỏ
- **Input**: n = 9
- **Expected Output**: `{"": "9 - Composite"}`
- **Priority**: High

#### TC_AKS_003: Kiểm tra số nguyên tố đặc biệt - 2
- **Mục tiêu**: Xác minh AKS xử lý đúng số nguyên tố nhỏ nhất
- **Input**: n = 2
- **Expected Output**: `{"": "2 - Prime"}`
- **Priority**: High

#### TC_AKS_004: Kiểm tra số nguyên tố đặc biệt - 3
- **Mục tiêu**: Xác minh AKS xử lý đúng số nguyên tố lẻ nhỏ nhất
- **Input**: n = 3
- **Expected Output**: `{"": "3 - Prime"}`
- **Priority**: High

#### TC_AKS_005: Kiểm tra số 1
- **Mục tiêu**: Xác minh AKS xử lý đúng trường hợp đặc biệt n=1
- **Input**: n = 1
- **Expected Output**: `{"": "1 - Prime"}` (theo implementation hiện tại)
- **Priority**: High
- **Note**: Theo toán học chuẩn, 1 không phải số nguyên tố, nhưng implementation hiện tại trả về Prime

#### TC_AKS_006: Kiểm tra số 0
- **Mục tiêu**: Xác minh AKS xử lý đúng trường hợp n=0
- **Input**: n = 0
- **Expected Output**: `{"": "0 - Composite"}`
- **Priority**: High

#### TC_AKS_007: Kiểm tra số chẵn lớn hơn 2
- **Mục tiêu**: Xác minh AKS nhận diện đúng số chẵn là hợp số
- **Input**: n = 100
- **Expected Output**: `{"": "100 - Composite"}`
- **Priority**: Medium

#### TC_AKS_008: Kiểm tra số nguyên tố lớn
- **Mục tiêu**: Xác minh AKS hoạt động với số nguyên tố lớn hơn
- **Input**: n = 97
- **Expected Output**: `{"": "97 - Prime"}`
- **Priority**: Medium

#### TC_AKS_009: Kiểm tra hợp số lớn
- **Mục tiêu**: Xác minh AKS nhận diện đúng hợp số lớn
- **Input**: n = 91 (7 * 13)
- **Expected Output**: `{"": "91 - Composite"}`
- **Priority**: Medium

### 1.2. Test Cases - Dữ liệu không hợp lệ

#### TC_AKS_E001: Kiểm tra input null
- **Mục tiêu**: Xác minh xử lý lỗi khi input null
- **Input**: n = None
- **Expected Output**: `{"Error": "Enter Again"}` hoặc error message
- **Priority**: High

#### TC_AKS_E002: Kiểm tra input số âm
- **Mục tiêu**: Xác minh xử lý lỗi khi input số âm
- **Input**: n = -5
- **Expected Output**: `"Enter Again"` hoặc `{"Error": "..."}`
- **Priority**: High

#### TC_AKS_E003: Kiểm tra input không phải số nguyên
- **Mục tiêu**: Xác minh xử lý lỗi khi input không phải số
- **Input**: n = "abc"
- **Expected Output**: `{"Error": "Input must be an integer"}`
- **Priority**: High

#### TC_AKS_E004: Kiểm tra input chuỗi rỗng
- **Mục tiêu**: Xác minh xử lý lỗi khi input rỗng
- **Input**: n = ""
- **Expected Output**: `{"Error": "..."}`
- **Priority**: Medium

---

## 2. CHỨC NĂNG 2: TÌM ƯỚC CHUNG LỚN NHẤT (GCD)

### 2.1. Test Cases - Dữ liệu hợp lệ

#### TC_GCD_001: Tính GCD của hai số có ước chung
- **Mục tiêu**: Xác minh thuật toán Euclid mở rộng hoạt động đúng
- **Input**: a = 48, b = 18
- **Expected Output**: `{"Result": "6"}`
- **Priority**: High

#### TC_GCD_002: Tính GCD của hai số nguyên tố cùng nhau
- **Mục tiêu**: Xác minh GCD = 1 khi hai số nguyên tố cùng nhau
- **Input**: a = 17, b = 19
- **Expected Output**: `{"Result": "1"}`
- **Priority**: High

#### TC_GCD_003: Tính GCD khi một số bằng 0
- **Mục tiêu**: Xác minh xử lý đúng khi b = 0
- **Input**: a = 25, b = 0
- **Expected Output**: `{"Result": "25"}`
- **Priority**: High

#### TC_GCD_004: Tính GCD của hai số bằng nhau
- **Mục tiêu**: Xác minh GCD(a,a) = a
- **Input**: a = 15, b = 15
- **Expected Output**: `{"Result": "15"}`
- **Priority**: Medium

#### TC_GCD_005: Tính GCD với số lớn
- **Mục tiêu**: Xác minh thuật toán hoạt động với số lớn
- **Input**: a = 100, b = 75
- **Expected Output**: `{"Result": "25"}`
- **Priority**: Medium

#### TC_GCD_006: Tính GCD khi a nhỏ hơn b
- **Mục tiêu**: Xác minh thuật toán hoạt động khi a < b
- **Input**: a = 18, b = 48
- **Expected Output**: `{"Result": "6"}`
- **Priority**: Medium

#### TC_GCD_007: Tính GCD với số 1
- **Mục tiêu**: Xác minh GCD(1, n) = 1
- **Input**: a = 1, b = 100
- **Expected Output**: `{"Result": "1"}`
- **Priority**: Low

### 2.2. Test Cases - Dữ liệu không hợp lệ

#### TC_GCD_E001: Kiểm tra input null
- **Mục tiêu**: Xác minh xử lý lỗi khi input null
- **Input**: a = None, b = 10
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_GCD_E002: Kiểm tra input số âm
- **Mục tiêu**: Xác minh xử lý lỗi khi input số âm
- **Input**: a = -10, b = 5
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_GCD_E003: Kiểm tra cả hai input số âm
- **Mục tiêu**: Xác minh xử lý lỗi khi cả hai số âm
- **Input**: a = -10, b = -5
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: Medium

#### TC_GCD_E004: Kiểm tra input không phải số
- **Mục tiêu**: Xác minh xử lý lỗi khi input không hợp lệ
- **Input**: a = "abc", b = 10
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

---

## 3. CHỨC NĂNG 3: LŨY THỪA MODULAR

### 3.1. Test Cases - Dữ liệu hợp lệ

#### TC_MODEXP_001: Tính lũy thừa modular cơ bản
- **Mục tiêu**: Xác minh thuật toán Square-and-Multiply
- **Input**: a = 2, b = 10, m = 1000
- **Expected Output**: `{"Result": "24"}` (2^10 = 1024, 1024 % 1000 = 24)
- **Priority**: High

#### TC_MODEXP_002: Tính với số mũ = 0
- **Mục tiêu**: Xác minh a^0 mod m = 1
- **Input**: a = 5, b = 0, m = 7
- **Expected Output**: `{"Result": "1"}`
- **Priority**: High

#### TC_MODEXP_003: Tính với số mũ = 1
- **Mục tiêu**: Xác minh a^1 mod m = a mod m
- **Input**: a = 5, b = 1, m = 7
- **Expected Output**: `{"Result": "5"}`
- **Priority**: High

#### TC_MODEXP_004: Tính với cơ số = 0
- **Mục tiêu**: Xác minh 0^b mod m = 0
- **Input**: a = 0, b = 5, m = 7
- **Expected Output**: `{"Result": "0"}`
- **Priority**: High

#### TC_MODEXP_005: Tính với modulo = 1
- **Mục tiêu**: Xác minh a^b mod 1 = 0
- **Input**: a = 5, b = 3, m = 1
- **Expected Output**: `{"Result": "0"}`
- **Priority**: Medium

#### TC_MODEXP_006: Tính với số lớn
- **Mục tiêu**: Xác minh thuật toán hoạt động với số lớn
- **Input**: a = 3, b = 4, m = 7
- **Expected Output**: `{"Result": "4"}` (3^4 = 81, 81 % 7 = 4)
- **Priority**: Medium

#### TC_MODEXP_007: Tính với kết quả = 0
- **Mục tiêu**: Xác minh trường hợp kết quả = 0
- **Input**: a = 2, b = 3, m = 8
- **Expected Output**: `{"Result": "0"}` (2^3 = 8, 8 % 8 = 0)
- **Priority**: Medium

### 3.2. Test Cases - Dữ liệu không hợp lệ

#### TC_MODEXP_E001: Kiểm tra input null
- **Mục tiêu**: Xác minh xử lý lỗi khi input null
- **Input**: a = None, b = 2, m = 5
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODEXP_E002: Kiểm tra modulo = 0
- **Mục tiêu**: Xác minh xử lý lỗi chia cho 0
- **Input**: a = 2, b = 3, m = 0
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODEXP_E003: Kiểm tra input số âm
- **Mục tiêu**: Xác minh xử lý lỗi số âm
- **Input**: a = -2, b = 3, m = 5
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODEXP_E004: Kiểm tra input không phải số
- **Mục tiêu**: Xác minh xử lý lỗi input không hợp lệ
- **Input**: a = "abc", b = 2, m = 5
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

---

## 4. CHỨC NĂNG 4: TÌM NGHỊCH ĐẢO MODULAR

### 4.1. Test Cases - Dữ liệu hợp lệ

#### TC_MODINV_001: Tìm nghịch đảo modular cơ bản
- **Mục tiêu**: Xác minh thuật toán tìm nghịch đảo đúng
- **Input**: a = 3, m = 11
- **Expected Output**: `{"Result": 4}` (3 * 4 = 12 ≡ 1 mod 11)
- **Priority**: High

#### TC_MODINV_002: Tìm nghịch đảo của 1
- **Mục tiêu**: Xác minh nghịch đảo của 1 là 1
- **Input**: a = 1, m = 100
- **Expected Output**: `{"Result": 1}`
- **Priority**: High

#### TC_MODINV_003: Tìm nghịch đảo với số lớn
- **Mục tiêu**: Xác minh thuật toán hoạt động với số lớn
- **Input**: a = 7, m = 26
- **Expected Output**: `{"Result": 15}` (7 * 15 = 105 ≡ 1 mod 26)
- **Priority**: Medium

#### TC_MODINV_004: Không tồn tại nghịch đảo (GCD ≠ 1)
- **Mục tiêu**: Xác minh phát hiện không tồn tại nghịch đảo
- **Input**: a = 4, m = 12
- **Expected Output**: `{"Result": "No modular multiplicative inverse"}`
- **Priority**: High

#### TC_MODINV_005: Tìm nghịch đảo số chẵn với modulo lẻ
- **Mục tiêu**: Xác minh thuật toán với số chẵn
- **Input**: a = 6, m = 11
- **Expected Output**: `{"Result": ...}` (nghịch đảo hợp lệ)
- **Priority**: Medium

### 4.2. Test Cases - Dữ liệu không hợp lệ

#### TC_MODINV_E001: Kiểm tra input null
- **Mục tiêu**: Xác minh xử lý lỗi input null
- **Input**: a = None, m = 11
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODINV_E002: Kiểm tra a = 0
- **Mục tiêu**: Xác minh 0 không có nghịch đảo
- **Input**: a = 0, m = 11
- **Expected Output**: `{"Result": "No modular multiplicative inverse"}`
- **Priority**: High

#### TC_MODINV_E003: Kiểm tra modulo = 0
- **Mục tiêu**: Xác minh xử lý lỗi m = 0
- **Input**: a = 3, m = 0
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODINV_E004: Kiểm tra modulo = 1
- **Mục tiêu**: Xác minh xử lý m = 1
- **Input**: a = 3, m = 1
- **Expected Output**: `{"Error": "Invalid input"}` hoặc kết quả đặc biệt
- **Priority**: Medium

#### TC_MODINV_E005: Kiểm tra input số âm
- **Mục tiêu**: Xác minh xử lý lỗi số âm
- **Input**: a = -3, m = 11
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

#### TC_MODINV_E006: Kiểm tra input không phải số
- **Mục tiêu**: Xác minh xử lý lỗi input không hợp lệ
- **Input**: a = "abc", m = 11
- **Expected Output**: `{"Error": "Invalid input"}`
- **Priority**: High

------------------------------

## 5. CHỨC NĂNG 5: MILLER-RABIN (HỖ TRỢ)

### 5.1. Test Cases - Kiểm tra thuật toán

#### TC_MR_001: Kiểm tra số nguyên tố nhỏ
- **Mục tiêu**: Xác minh Miller-Rabin nhận diện số nguyên tố
- **Input**: n = 17, k = 1000
- **Expected Output**: True
- **Priority**: High

#### TC_MR_002: Kiểm tra hợp số
- **Mục tiêu**: Xác minh Miller-Rabin nhận diện hợp số
- **Input**: n = 15, k = 1000
- **Expected Output**: False
- **Priority**: High

#### TC_MR_003: Kiểm tra số nguyên tố lớn
- **Mục tiêu**: Xác minh với số lớn hơn
- **Input**: n = 97, k = 1000
- **Expected Output**: True
- **Priority**: Medium

#### TC_MR_004: Kiểm tra số Carmichael (561)
- **Mục tiêu**: Xác minh xử lý số Carmichael (pseudoprime)
- **Input**: n = 561, k = 1000
- **Expected Output**: False (561 là hợp số)
- **Priority**: Medium

---

## 6. CHỨC NĂNG 6: ELLIPTIC CURVE OPERATIONS

### 6.1. Test Cases - ECC Operations

#### TC_ECC_001: Nhân đôi điểm (Double)
- **Mục tiêu**: Xác minh phép nhân đôi điểm trên đường cong
- **Input**: point = (2, 5), a = 2, p = 17
- **Expected Output**: Điểm 2P hợp lệ trên đường cong
- **Priority**: High

#### TC_ECC_002: Cộng hai điểm (Add)
- **Mục tiêu**: Xác minh phép cộng điểm
- **Input**: P1 = (2, 5), P2 = (3, 1), a = 2, p = 17
- **Expected Output**: Điểm P1 + P2 hợp lệ
- **Priority**: High

#### TC_ECC_003: Nhân vô hướng (Double and Add)
- **Mục tiêu**: Xác minh phép nhân điểm với số nguyên
- **Input**: point = (2, 5), n = 3, a = 2, p = 17
- **Expected Output**: Điểm 3P hợp lệ
- **Priority**: High

#### TC_ECC_004: Tìm điểm trên đường cong
- **Mục tiêu**: Xác minh tìm được điểm hợp lệ
- **Input**: p = 17, a = 2, b = 2
- **Expected Output**: Một điểm (x, y) thỏa mãn y² = x³ + 2x + 2 (mod 17)
- **Priority**: Medium

#### TC_ECC_005: Kiểm tra điểm nằm trên đường cong
- **Mục tiêu**: Xác minh validation điểm
- **Input**: point = (2, 5), a = 2, b = 2, p = 17
- **Expected Output**: True/False dựa trên phương trình
- **Priority**: Medium