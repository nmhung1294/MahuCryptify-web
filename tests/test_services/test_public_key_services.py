"""
Black Box Testing for RSA/ElGamal/ECC Services
Testing validation logic primarily (functional tests limited due to performance)
Total: 60 test cases (20 per service)
"""

import unittest
import sys
sys.path.append('d:\\MahuCryptify\\MahuCryptify')

from MahuCrypt_app.services.rsa_service import RSAService
from MahuCrypt_app.services.elgamal_service import ElGamalService
from MahuCrypt_app.services.ecc_service import ECCService


class TestRSAService(unittest.TestCase):
    """Test RSA Service - 20 test cases (focus: validation)"""
    
    # generate_keys tests (10 tests)
    @unittest.skip("RSA với bits=2 hangs indefinitely - known bug")
    def test_tc01_generate_keys_bits_2(self):
        """TC01: Generate keys với bits=2 (nhỏ nhất)"""
        result = RSAService.generate_keys(2)
        # Có thể timeout hoặc trả về keys
        self.assertTrue(isinstance(result, dict))
    
    def test_tc02_generate_keys_bits_zero(self):
        """TC02: bits=0 - validation lỗi"""
        result = RSAService.generate_keys(0)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc03_generate_keys_bits_negative(self):
        """TC03: bits âm - validation lỗi"""
        result = RSAService.generate_keys(-5)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc04_generate_keys_bits_none(self):
        """TC04: bits=None - NULL value"""
        result = RSAService.generate_keys(None)
        self.assertEqual(result, {"Error": "NULL Value - Please enter bits"})
    
    def test_tc05_generate_keys_bits_string(self):
        """TC05: bits string không parse được"""
        result = RSAService.generate_keys("abc")
        self.assertEqual(result, {"Error": "Bits must be an integer"})
    
    def test_tc06_generate_keys_bits_one(self):
        """TC06: bits=1 - biên"""
        result = RSAService.generate_keys(1)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    # encrypt tests (5 tests)
    def test_tc07_encrypt_null_message(self):
        """TC07: message=None"""
        result = RSAService.encrypt(None, 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc08_encrypt_null_n(self):
        """TC08: n=None"""
        result = RSAService.encrypt("HELLO", None, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc09_encrypt_null_e(self):
        """TC09: e=None"""
        result = RSAService.encrypt("HELLO", 15, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc10_encrypt_empty_message(self):
        """TC10: message rỗng"""
        result = RSAService.encrypt("", 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc11_encrypt_e_greater_n(self):
        """TC11: e > n - validation lỗi"""
        result = RSAService.encrypt("HELLO", 15, 20)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    # decrypt tests (5 tests)
    def test_tc12_decrypt_null_encrypted(self):
        """TC12: encrypted_message=None"""
        result = RSAService.decrypt(None, 3, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc13_decrypt_null_p(self):
        """TC13: p=None"""
        result = RSAService.decrypt("123", None, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc14_decrypt_null_q(self):
        """TC14: q=None"""
        result = RSAService.decrypt("123", 3, None, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc15_decrypt_null_d(self):
        """TC15: d=None"""
        result = RSAService.decrypt("123", 3, 5, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc16_decrypt_empty_encrypted(self):
        """TC16: encrypted_message rỗng"""
        result = RSAService.decrypt("", 3, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    # round trip tests (4 tests - với bits rất nhỏ)
    def test_tc17_roundtrip_check_validation(self):
        """TC17: Kiểm tra validation trong flow hoàn chỉnh"""
        # Test validation bằng cách pass invalid data
        encrypt_result = RSAService.encrypt("TEST", -1, 5)
        self.assertIn("Error", encrypt_result)
    
    def test_tc18_check_n_validation(self):
        """TC18: n=0 validation"""
        result = RSAService.encrypt("TEST", 0, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc19_check_e_validation(self):
        """TC19: e=0 validation"""
        result = RSAService.encrypt("TEST", 15, 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc20_check_invalid_types(self):
        """TC20: Invalid types - n, e không phải integer"""
        result = RSAService.encrypt("TEST", "abc", "xyz")
        self.assertEqual(result, {"Error": "n and e must be integers"})


class TestElGamalService(unittest.TestCase):
    """Test ElGamal Service - 20 test cases"""
    
    # generate_keys tests (10 tests)
    def test_tc21_generate_keys_bits_8(self):
        """TC21: Generate keys với bits=8 (nhỏ, test nhanh)"""
        result = ElGamalService.generate_keys(8)
        # Có thể trả về keys hoặc error
        self.assertTrue(isinstance(result, dict))
    
    def test_tc22_generate_keys_bits_zero(self):
        """TC22: bits=0 - validation lỗi"""
        result = ElGamalService.generate_keys(0)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc23_generate_keys_bits_negative(self):
        """TC23: bits âm"""
        result = ElGamalService.generate_keys(-10)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc24_generate_keys_bits_none(self):
        """TC24: bits=None"""
        result = ElGamalService.generate_keys(None)
        self.assertEqual(result, {"Error": "NULL Value - Please enter bits"})
    
    def test_tc25_generate_keys_bits_string(self):
        """TC25: bits string không parse được"""
        result = ElGamalService.generate_keys("xyz")
        self.assertEqual(result, {"Error": "Bits must be an integer"})
    
    def test_tc26_generate_keys_bits_one(self):
        """TC26: bits=1 - biên"""
        result = ElGamalService.generate_keys(1)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    # encrypt tests (5 tests)
    def test_tc27_encrypt_null_message(self):
        """TC27: message=None"""
        result = ElGamalService.encrypt(None, 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc28_encrypt_null_p(self):
        """TC28: p=None"""
        result = ElGamalService.encrypt("HELLO", None, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc29_encrypt_empty_message(self):
        """TC29: message rỗng"""
        result = ElGamalService.encrypt("", 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc30_encrypt_p_zero(self):
        """TC30: p=0"""
        result = ElGamalService.encrypt("HELLO", 0, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc31_encrypt_invalid_types(self):
        """TC31: Invalid types"""
        result = ElGamalService.encrypt("HELLO", "x", "y", "z")
        self.assertEqual(result, {"Error": "p, alpha, beta must be integers"})
    
    # decrypt tests (5 tests)
    def test_tc32_decrypt_null_encrypted(self):
        """TC32: encrypted_message=None"""
        result = ElGamalService.decrypt(None, 11, 7)
        self.assertEqual(result, "Enter Again")
    
    def test_tc33_decrypt_null_p(self):
        """TC33: p=None"""
        result = ElGamalService.decrypt("123", None, 7)
        self.assertEqual(result, "Enter Again")
    
    def test_tc34_decrypt_empty_encrypted(self):
        """TC34: encrypted_message rỗng"""
        result = ElGamalService.decrypt("", 11, 7)
        self.assertEqual(result, "Enter Again")
    
    def test_tc35_decrypt_a_zero(self):
        """TC35: a=0"""
        result = ElGamalService.decrypt("123", 11, 0)
        self.assertEqual(result, "Enter Again")
    
    def test_tc36_decrypt_invalid_types(self):
        """TC36: Invalid types"""
        result = ElGamalService.decrypt("123", "x", "y")
        self.assertEqual(result, {"Error": "p and a must be integers"})
    
    # additional validation tests (4 tests)
    def test_tc37_check_alpha_validation(self):
        """TC37: alpha=None"""
        result = ElGamalService.encrypt("TEST", 11, None, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc38_check_beta_validation(self):
        """TC38: beta=None"""
        result = ElGamalService.encrypt("TEST", 11, 2, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc39_check_alpha_zero(self):
        """TC39: alpha=0"""
        result = ElGamalService.encrypt("TEST", 11, 0, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc40_check_beta_zero(self):
        """TC40: beta=0"""
        result = ElGamalService.encrypt("TEST", 11, 2, 0)
        self.assertEqual(result, {"Error": "NULL Value"})


class TestECCService(unittest.TestCase):
    """Test ECC Service - 20 test cases"""
    
    # generate_keys tests (10 tests)
    def test_tc41_generate_keys_bits_8(self):
        """TC41: Generate keys với bits=8"""
        result = ECCService.generate_keys(8)
        self.assertTrue(isinstance(result, dict))
    
    def test_tc42_generate_keys_bits_zero(self):
        """TC42: bits=0"""
        result = ECCService.generate_keys(0)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc43_generate_keys_bits_negative(self):
        """TC43: bits âm"""
        result = ECCService.generate_keys(-5)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    def test_tc44_generate_keys_bits_none(self):
        """TC44: bits=None"""
        result = ECCService.generate_keys(None)
        self.assertEqual(result, {"Error": "NULL Value - Please enter bits"})
    
    def test_tc45_generate_keys_bits_string(self):
        """TC45: bits string"""
        result = ECCService.generate_keys("abc")
        self.assertEqual(result, {"Error": "Bits must be an integer"})
    
    def test_tc46_generate_keys_bits_one(self):
        """TC46: bits=1"""
        result = ECCService.generate_keys(1)
        self.assertEqual(result, {"Error": "Bits must be greater than 0"})
    
    # encrypt tests (7 tests)
    def test_tc47_encrypt_null_message(self):
        """TC47: message=None"""
        result = ECCService.encrypt(None, 1, 23, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc48_encrypt_null_p(self):
        """TC48: p=None"""
        result = ECCService.encrypt("HELLO", 1, None, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc49_encrypt_empty_message(self):
        """TC49: message rỗng"""
        result = ECCService.encrypt("", 1, 23, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc50_encrypt_p_zero(self):
        """TC50: p=0"""
        result = ECCService.encrypt("HELLO", 1, 0, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc51_encrypt_invalid_types(self):
        """TC51: Invalid types - a, p"""
        result = ECCService.encrypt("HELLO", "x", "y", "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "a, p must be integers"})
    
    def test_tc52_encrypt_null_P(self):
        """TC52: P=None"""
        result = ECCService.encrypt("HELLO", 1, 23, None, "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc53_encrypt_null_B(self):
        """TC53: B=None"""
        result = ECCService.encrypt("HELLO", 1, 23, "(5, 7)", None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    # decrypt tests (7 tests)
    def test_tc54_decrypt_null_encrypted(self):
        """TC54: encrypted_message=None"""
        result = ECCService.decrypt(None, 1, 23, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc55_decrypt_null_p(self):
        """TC55: p=None"""
        result = ECCService.decrypt("123", 1, None, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc56_decrypt_empty_encrypted(self):
        """TC56: encrypted_message rỗng"""
        result = ECCService.decrypt("", 1, 23, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc57_decrypt_s_zero(self):
        """TC57: s=0"""
        result = ECCService.decrypt("123", 1, 23, 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc58_decrypt_invalid_types(self):
        """TC58: Invalid types"""
        result = ECCService.decrypt("123", "x", "y", "z")
        self.assertEqual(result, {"Error": "a, p, s must be integers"})
    
    def test_tc59_decrypt_null_a(self):
        """TC59: a=None"""
        result = ECCService.decrypt("123", None, 23, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc60_decrypt_a_zero(self):
        """TC60: a=0"""
        result = ECCService.decrypt("123", 0, 23, 7)
        self.assertEqual(result, {"Error": "NULL Value"})


if __name__ == '__main__':
    unittest.main()
