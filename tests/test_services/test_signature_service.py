"""
Black Box Testing for Signature Service
Testing 6 operations: RSA sign/verify, ElGamal sign/verify, ECDSA sign/verify
Total: 60 test cases (10 per operation - focus on validation)
"""

import unittest
import sys
sys.path.append('d:\\MahuCryptify\\MahuCryptify')

from MahuCrypt_app.services.signature_service import SignatureService


class TestRSASignature(unittest.TestCase):
    """Test RSA signature - 20 test cases"""
    
    # sign_with_rsa tests (10 tests)
    def test_tc01_sign_null_message(self):
        """TC01: message=None"""
        result = SignatureService.sign_with_rsa(None, 3, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc02_sign_null_p(self):
        """TC02: p=None"""
        result = SignatureService.sign_with_rsa("TEST", None, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc03_sign_null_q(self):
        """TC03: q=None"""
        result = SignatureService.sign_with_rsa("TEST", 3, None, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc04_sign_null_d(self):
        """TC04: d=None"""
        result = SignatureService.sign_with_rsa("TEST", 3, 5, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc05_sign_empty_message(self):
        """TC05: message rỗng"""
        result = SignatureService.sign_with_rsa("", 3, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc06_sign_p_zero(self):
        """TC06: p=0"""
        result = SignatureService.sign_with_rsa("TEST", 0, 5, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc07_sign_invalid_types(self):
        """TC07: Invalid types"""
        result = SignatureService.sign_with_rsa("TEST", "x", "y", "z")
        self.assertEqual(result, {"Error": "p, q, d must be integers"})
    
    def test_tc08_sign_p_not_prime(self):
        """TC08: p không phải số nguyên tố"""
        result = SignatureService.sign_with_rsa("TEST", 4, 5, 3)
        self.assertEqual(result, {"Error": "p is not prime"})
    
    def test_tc09_sign_q_not_prime(self):
        """TC09: q không phải số nguyên tố"""
        result = SignatureService.sign_with_rsa("TEST", 3, 6, 3)
        self.assertEqual(result, {"Error": "q is not prime"})
    
    def test_tc10_sign_d_zero(self):
        """TC10: d=0"""
        result = SignatureService.sign_with_rsa("TEST", 3, 5, 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    # verify_rsa_signature tests (10 tests)
    def test_tc11_verify_null_hash(self):
        """TC11: hash_message=None"""
        result = SignatureService.verify_rsa_signature(None, "[1,2,3]", 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc12_verify_null_signed(self):
        """TC12: signed_message=None"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", None, 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc13_verify_null_n(self):
        """TC13: n=None"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "[1,2,3]", None, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc14_verify_null_e(self):
        """TC14: e=None"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "[1,2,3]", 15, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc15_verify_empty_hash(self):
        """TC15: hash_message rỗng"""
        result = SignatureService.verify_rsa_signature("", "[1,2,3]", 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc16_verify_n_zero(self):
        """TC16: n=0"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "[1,2,3]", 0, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc17_verify_invalid_types(self):
        """TC17: Invalid types - n, e"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "[1,2,3]", "x", "y")
        self.assertEqual(result, {"Error": "n and e must be integers"})
    
    def test_tc18_verify_e_zero(self):
        """TC18: e=0"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "[1,2,3]", 15, 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc19_verify_empty_signed(self):
        """TC19: signed_message rỗng"""
        result = SignatureService.verify_rsa_signature("[1,2,3]", "", 15, 3)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc20_verify_invalid_hash_format(self):
        """TC20: hash format không hợp lệ"""
        result = SignatureService.verify_rsa_signature("not_a_list", "[1,2,3]", 15, 3)
        # Có thể trả về error hoặc parse thất bại
        self.assertTrue(isinstance(result, dict))


class TestElGamalSignature(unittest.TestCase):
    """Test ElGamal signature - 20 test cases"""
    
    # sign_with_elgamal tests (10 tests)
    def test_tc21_sign_null_message(self):
        """TC21: message=None"""
        result = SignatureService.sign_with_elgamal(None, 11, 2, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc22_sign_null_p(self):
        """TC22: p=None"""
        result = SignatureService.sign_with_elgamal("TEST", None, 2, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc23_sign_null_alpha(self):
        """TC23: alpha=None"""
        result = SignatureService.sign_with_elgamal("TEST", 11, None, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc24_sign_null_a(self):
        """TC24: a=None"""
        result = SignatureService.sign_with_elgamal("TEST", 11, 2, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc25_sign_empty_message(self):
        """TC25: message rỗng"""
        result = SignatureService.sign_with_elgamal("", 11, 2, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc26_sign_p_zero(self):
        """TC26: p=0"""
        result = SignatureService.sign_with_elgamal("TEST", 0, 2, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc27_sign_invalid_types(self):
        """TC27: Invalid types"""
        result = SignatureService.sign_with_elgamal("TEST", "x", "y", "z")
        self.assertEqual(result, {"Error": "p, alpha, a must be integers"})
    
    def test_tc28_sign_p_not_prime(self):
        """TC28: p không phải số nguyên tố"""
        result = SignatureService.sign_with_elgamal("TEST", 10, 2, 7)
        self.assertEqual(result, {"Error": "p is not prime"})
    
    def test_tc29_sign_alpha_zero(self):
        """TC29: alpha=0"""
        result = SignatureService.sign_with_elgamal("TEST", 11, 0, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc30_sign_a_zero(self):
        """TC30: a=0"""
        result = SignatureService.sign_with_elgamal("TEST", 11, 2, 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    # verify_elgamal_signature tests (10 tests)
    def test_tc31_verify_null_hash(self):
        """TC31: hash_message=None"""
        result = SignatureService.verify_elgamal_signature(None, "([1,2],[3,4])", 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc32_verify_null_signed(self):
        """TC32: signed_message=None"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", None, 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc33_verify_null_p(self):
        """TC33: p=None"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", None, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc34_verify_null_alpha(self):
        """TC34: alpha=None"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", 11, None, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc35_verify_null_beta(self):
        """TC35: beta=None"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", 11, 2, None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc36_verify_empty_hash(self):
        """TC36: hash_message rỗng"""
        result = SignatureService.verify_elgamal_signature("", "([1,2],[3,4])", 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc37_verify_p_zero(self):
        """TC37: p=0"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", 0, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc38_verify_invalid_types(self):
        """TC38: Invalid types"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", "x", "y", "z")
        self.assertEqual(result, {"Error": "p, alpha, beta must be integers"})
    
    def test_tc39_verify_p_not_prime(self):
        """TC39: p không phải số nguyên tố"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "([1,2],[3,4])", 10, 2, 5)
        self.assertEqual(result, {"Error": "p is not prime"})
    
    def test_tc40_verify_empty_signed(self):
        """TC40: signed_message rỗng"""
        result = SignatureService.verify_elgamal_signature("[1,2,3]", "", 11, 2, 5)
        self.assertEqual(result, {"Error": "NULL Value"})


class TestECDSASignature(unittest.TestCase):
    """Test ECDSA signature - 20 test cases"""
    
    # sign_with_ecdsa tests (10 tests)
    def test_tc41_sign_null_message(self):
        """TC41: message=None"""
        result = SignatureService.sign_with_ecdsa(None, 23, 28, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc42_sign_null_p(self):
        """TC42: p=None"""
        result = SignatureService.sign_with_ecdsa("TEST", None, 28, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc43_sign_null_q(self):
        """TC43: q=None"""
        result = SignatureService.sign_with_ecdsa("TEST", 23, None, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc44_sign_null_d(self):
        """TC44: d=None"""
        result = SignatureService.sign_with_ecdsa("TEST", 23, 28, 1, 1, "(5, 7)", None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc45_sign_empty_message(self):
        """TC45: message rỗng"""
        result = SignatureService.sign_with_ecdsa("", 23, 28, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc46_sign_p_zero(self):
        """TC46: p=0"""
        result = SignatureService.sign_with_ecdsa("TEST", 0, 28, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc47_sign_invalid_types(self):
        """TC47: Invalid types - p, q, a, b, d"""
        result = SignatureService.sign_with_ecdsa("TEST", "x", "y", "z", "w", "(5, 7)", "d")
        self.assertEqual(result, {"Error": "p, q, a, b, d must be integers"})
    
    def test_tc48_sign_null_G(self):
        """TC48: G=None"""
        result = SignatureService.sign_with_ecdsa("TEST", 23, 28, 1, 1, None, 7)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc49_sign_d_zero(self):
        """TC49: d=0"""
        result = SignatureService.sign_with_ecdsa("TEST", 23, 28, 1, 1, "(5, 7)", 0)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc50_sign_p_not_prime(self):
        """TC50: p không phải số nguyên tố"""
        result = SignatureService.sign_with_ecdsa("TEST", 20, 28, 1, 1, "(5, 7)", 7)
        self.assertEqual(result, {"Error": "p is not prime"})
    
    # verify_ecdsa_signature tests (10 tests)
    def test_tc51_verify_null_hash(self):
        """TC51: hash_message=None"""
        result = SignatureService.verify_ecdsa_signature(None, "([1,2],[3,4])", 23, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc52_verify_null_signed(self):
        """TC52: signed_message=None"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", None, 23, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc53_verify_null_p(self):
        """TC53: p=None"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", None, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc54_verify_null_q(self):
        """TC54: q=None"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", 23, None, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc55_verify_empty_hash(self):
        """TC55: hash_message rỗng"""
        result = SignatureService.verify_ecdsa_signature("", "([1,2],[3,4])", 23, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc56_verify_p_zero(self):
        """TC56: p=0"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", 0, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc57_verify_invalid_types(self):
        """TC57: Invalid types"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", "x", "y", "z", "w", "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "p, q, a, b must be integers"})
    
    def test_tc58_verify_null_G(self):
        """TC58: G=None"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", 23, 28, 1, 1, None, "(10, 2)")
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc59_verify_null_Q(self):
        """TC59: Q=None"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", 23, 28, 1, 1, "(5, 7)", None)
        self.assertEqual(result, {"Error": "NULL Value"})
    
    def test_tc60_verify_p_not_prime(self):
        """TC60: p không phải số nguyên tố"""
        result = SignatureService.verify_ecdsa_signature("[1,2,3]", "([1,2],[3,4])", 20, 28, 1, 1, "(5, 7)", "(10, 2)")
        self.assertEqual(result, {"Error": "p is not prime"})


if __name__ == '__main__':
    unittest.main()
