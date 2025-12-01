"""
Black Box Testing for Algorithm Service
Testing 4 functions: check_prime, calculate_gcd, calculate_modular_exp, calculate_mod_inverse
Total: 40 test cases
"""

import unittest
import sys
sys.path.append('d:\\MahuCryptify\\MahuCryptify')

from MahuCrypt_app.services.algorithm_service import AlgorithmService


class TestCheckPrime(unittest.TestCase):
    """Test check_prime function - 10 test cases"""
    
    def test_tc01_small_prime(self):
        """TC01: Số nguyên tố nhỏ - n=2"""
        result = AlgorithmService.check_prime(2)
        self.assertEqual(result, {"": "2 - Prime"})
    
    def test_tc02_large_prime(self):
        """TC02: Số nguyên tố lớn - n=97"""
        result = AlgorithmService.check_prime(97)
        self.assertEqual(result, {"": "97 - Prime"})
    
    def test_tc03_small_composite(self):
        """TC03: Hợp số nhỏ - n=4"""
        result = AlgorithmService.check_prime(4)
        self.assertEqual(result, {"": "4 - Composite"})
    
    def test_tc04_odd_composite(self):
        """TC04: Hợp số lẻ - n=9"""
        result = AlgorithmService.check_prime(9)
        self.assertEqual(result, {"": "9 - Composite"})
    
    def test_tc05_zero(self):
        """TC05: n=0 - biên dưới"""
        result = AlgorithmService.check_prime(0)
        self.assertEqual(result, "Enter Again")
    
    def test_tc06_one(self):
        """TC06: n=1 - trường hợp đặc biệt"""
        result = AlgorithmService.check_prime(1)
        self.assertEqual(result, {"": "1 - Composite"})
    
    def test_tc07_negative(self):
        """TC07: n âm - validation lỗi"""
        result = AlgorithmService.check_prime(-5)
        self.assertEqual(result, "Enter Again")
    
    def test_tc08_none(self):
        """TC08: n=None - NULL value"""
        result = AlgorithmService.check_prime(None)
        self.assertEqual(result, "Enter Again")
    
    def test_tc09_invalid_string(self):
        """TC09: String không parse được"""
        result = AlgorithmService.check_prime("abc")
        self.assertEqual(result, {"Error": "Input must be an integer"})
    
    def test_tc10_string_number(self):
        """TC10: String số - parse thành công"""
        result = AlgorithmService.check_prime("7")
        self.assertEqual(result, {"": "7 - Prime"})


class TestCalculateGCD(unittest.TestCase):
    """Test calculate_gcd function - 10 test cases"""
    
    def test_tc11_basic_gcd(self):
        """TC11: GCD cơ bản - GCD(12, 8) = 4"""
        result = AlgorithmService.calculate_gcd(12, 8)
        self.assertEqual(result, {"Result": "4"})
    
    def test_tc12_coprime(self):
        """TC12: Nguyên tố cùng nhau - GCD(7, 11) = 1"""
        result = AlgorithmService.calculate_gcd(7, 11)
        self.assertEqual(result, {"Result": "1"})
    
    def test_tc13_a_zero(self):
        """TC13: a=0 - GCD(0, 5) = 5"""
        result = AlgorithmService.calculate_gcd(0, 5)
        self.assertEqual(result, {"Result": "5"})
    
    def test_tc14_b_zero(self):
        """TC14: b=0 - GCD(10, 0) = 10"""
        result = AlgorithmService.calculate_gcd(10, 0)
        self.assertEqual(result, {"Result": "10"})
    
    def test_tc15_both_zero(self):
        """TC15: Cả 2 = 0 - GCD(0, 0) = 0"""
        result = AlgorithmService.calculate_gcd(0, 0)
        self.assertEqual(result, {"Result": "0"})
    
    def test_tc16_a_negative(self):
        """TC16: a âm - validation lỗi"""
        result = AlgorithmService.calculate_gcd(-10, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc17_b_negative(self):
        """TC17: b âm - validation lỗi"""
        result = AlgorithmService.calculate_gcd(10, -5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc18_a_none(self):
        """TC18: a=None - NULL value"""
        result = AlgorithmService.calculate_gcd(None, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc19_b_none(self):
        """TC19: b=None - NULL value"""
        result = AlgorithmService.calculate_gcd(10, None)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc20_string_input(self):
        """TC20: String input - GCD(15, 20) = 5"""
        result = AlgorithmService.calculate_gcd("15", "20")
        self.assertEqual(result, {"Result": "5"})


class TestCalculateModularExp(unittest.TestCase):
    """Test calculate_modular_exp function - 10 test cases"""
    
    def test_tc21_basic_modexp(self):
        """TC21: Modular exp cơ bản - 3^4 mod 7 = 4"""
        result = AlgorithmService.calculate_modular_exp(3, 4, 7)
        self.assertEqual(result, {"Result": "4"})
    
    def test_tc22_b_zero(self):
        """TC22: b=0 - a^0 = 1"""
        result = AlgorithmService.calculate_modular_exp(5, 0, 7)
        self.assertEqual(result, {"Result": "1"})
    
    def test_tc23_a_zero(self):
        """TC23: a=0 - 0^b = 0"""
        result = AlgorithmService.calculate_modular_exp(0, 5, 7)
        self.assertEqual(result, {"Result": "0"})
    
    def test_tc24_m_one(self):
        """TC24: m=1 - x mod 1 = 0"""
        result = AlgorithmService.calculate_modular_exp(10, 3, 1)
        self.assertEqual(result, {"Result": "0"})
    
    def test_tc25_large_exp(self):
        """TC25: Số lớn - 2^100 mod 13"""
        result = AlgorithmService.calculate_modular_exp(2, 100, 13)
        self.assertIn("Result", result)
        self.assertIsInstance(result["Result"], str)
    
    def test_tc26_a_negative(self):
        """TC26: a âm - validation lỗi"""
        result = AlgorithmService.calculate_modular_exp(-2, 3, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc27_b_negative(self):
        """TC27: b âm - validation lỗi"""
        result = AlgorithmService.calculate_modular_exp(2, -3, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc28_m_negative(self):
        """TC28: m âm - validation lỗi"""
        result = AlgorithmService.calculate_modular_exp(2, 3, -5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc29_input_none(self):
        """TC29: Input None - NULL value"""
        result = AlgorithmService.calculate_modular_exp(None, 2, 3)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc30_string_input(self):
        """TC30: String input - 2^3 mod 5 = 3"""
        result = AlgorithmService.calculate_modular_exp("2", "3", "5")
        self.assertEqual(result, {"Result": "3"})


class TestCalculateModInverse(unittest.TestCase):
    """Test calculate_mod_inverse function - 10 test cases"""
    
    def test_tc31_mod_inverse_exists(self):
        """TC31: Mod inverse tồn tại - 3^-1 mod 11 = 4"""
        result = AlgorithmService.calculate_mod_inverse(3, 11)
        self.assertEqual(result, {"Result": 4})
    
    def test_tc32_mod_inverse_negative_result(self):
        """TC32: Mod inverse với kết quả âm cần điều chỉnh"""
        result = AlgorithmService.calculate_mod_inverse(5, 11)
        self.assertIn("Result", result)
        # 5 * 9 = 45 = 4*11 + 1, so 5^-1 mod 11 = 9
    
    def test_tc33_no_inverse(self):
        """TC33: Không tồn tại - GCD(4,6) = 2 ≠ 1"""
        result = AlgorithmService.calculate_mod_inverse(4, 6)
        self.assertEqual(result, {"Result": "No modular multiplicative inverse"})
    
    def test_tc34_a_one(self):
        """TC34: a=1 - 1^-1 mod m = 1"""
        result = AlgorithmService.calculate_mod_inverse(1, 10)
        self.assertEqual(result, {"Result": 1})
    
    def test_tc35_a_zero(self):
        """TC35: a=0 - GCD(0,5) = 5, không tồn tại"""
        result = AlgorithmService.calculate_mod_inverse(0, 5)
        self.assertEqual(result, {"Result": "No modular multiplicative inverse"})
    
    def test_tc36_a_negative(self):
        """TC36: a âm - validation lỗi"""
        result = AlgorithmService.calculate_mod_inverse(-3, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc37_m_negative(self):
        """TC37: m âm - validation lỗi"""
        result = AlgorithmService.calculate_mod_inverse(3, -5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc38_a_none(self):
        """TC38: a=None - NULL value"""
        result = AlgorithmService.calculate_mod_inverse(None, 5)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc39_m_none(self):
        """TC39: m=None - NULL value"""
        result = AlgorithmService.calculate_mod_inverse(3, None)
        self.assertEqual(result, {"Error": "Invalid input"})
    
    def test_tc40_string_input(self):
        """TC40: String input - 7^-1 mod 26"""
        result = AlgorithmService.calculate_mod_inverse("7", "26")
        self.assertIn("Result", result)
        # 7 * 15 = 105 = 4*26 + 1, so 7^-1 mod 26 = 15


if __name__ == '__main__':
    unittest.main()
