"""
Unit Test for modular_exponentiation function - Black Box Testing
Module: MahuCrypt_app.cryptography.algos
Function: modular_exponentiation(b, n, m)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Calculate b^n mod m efficiently
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.algos import modular_exponentiation


class TestModularExponentiation(unittest.TestCase):
    """
    Black Box Testing for Modular Exponentiation
    
    Test Plan:
    - PE1: n = 0 (base case)
    - PE2: n = 1 (identity)
    - PE3: n chẵn (even exponent)
    - PE4: n lẻ (odd exponent)
    - PE5: b = 0
    - PE6: b = 1
    - PE7: m = 1
    - PE8: Large numbers (performance)
    - Boundary: Edge cases
    """
    
    # TC01: PE1 - Exponent = 0
    def test_tc01_exponent_zero(self):
        """Test case TC01: b^0 mod m = 1 for any b > 0"""
        result = modular_exponentiation(5, 0, 7)
        self.assertEqual(result, 1, "Any number to power 0 should be 1")
        
        result = modular_exponentiation(100, 0, 13)
        self.assertEqual(result, 1)
    
    # TC02: PE2 - Exponent = 1
    def test_tc02_exponent_one(self):
        """Test case TC02: b^1 mod m = b mod m"""
        result = modular_exponentiation(5, 1, 7)
        self.assertEqual(result, 5, "5^1 mod 7 should be 5")
        
        result = modular_exponentiation(10, 1, 7)
        self.assertEqual(result, 3, "10^1 mod 7 should be 3")
    
    # TC03: PE3 - Even exponent
    def test_tc03_even_exponent(self):
        """Test case TC03: Even exponent (2^10 mod 1000)"""
        result = modular_exponentiation(2, 10, 1000)
        expected = (2 ** 10) % 1000
        self.assertEqual(result, expected, f"2^10 mod 1000 should be {expected}")
    
    # TC04: PE4 - Odd exponent
    def test_tc04_odd_exponent(self):
        """Test case TC04: Odd exponent (3^7 mod 100)"""
        result = modular_exponentiation(3, 7, 100)
        expected = (3 ** 7) % 100
        self.assertEqual(result, expected, f"3^7 mod 100 should be {expected}")
    
    # TC05: PE5 - Base = 0
    def test_tc05_base_zero(self):
        """Test case TC05: 0^n mod m = 0 for n > 0"""
        result = modular_exponentiation(0, 5, 7)
        self.assertEqual(result, 0, "0^5 mod 7 should be 0")
    
    # TC06: PE6 - Base = 1
    def test_tc06_base_one(self):
        """Test case TC06: 1^n mod m = 1"""
        result = modular_exponentiation(1, 100, 7)
        self.assertEqual(result, 1, "1^100 mod 7 should be 1")
    
    # TC07: PE7 - Modulus = 1
    def test_tc07_modulus_one(self):
        """Test case TC07: b^n mod 1 = 0"""
        result = modular_exponentiation(5, 10, 1)
        self.assertEqual(result, 0, "Any number mod 1 should be 0")
    
    # TC08: RSA encryption example
    def test_tc08_rsa_encryption_example(self):
        """Test case TC08: Real RSA encryption scenario"""
        # Example: Encrypt message 42 with public key (e=7, n=187)
        # 42^7 mod 187
        result = modular_exponentiation(42, 7, 187)
        self.assertEqual(result, 15, "RSA encryption example failed")
    
    # TC09: Large exponent (performance test)
    def test_tc09_large_exponent(self):
        """Test case TC09: Large exponent - Performance test"""
        # Calculate 2^1000 mod 10^9+7
        result = modular_exponentiation(2, 1000, 1000000007)
        # Verify it's a valid result
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 1000000007)
    
    # TC10: Very large numbers (BigInt test)
    def test_tc10_very_large_numbers(self):
        """Test case TC10: Very large base and modulus"""
        b = 123456789
        n = 987654321
        m = 1000000007
        result = modular_exponentiation(b, n, m)
        
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, m)
    
    # TC11: Fermat's Little Theorem verification
    def test_tc11_fermats_little_theorem(self):
        """Test case TC11: Verify Fermat's Little Theorem (a^(p-1) mod p = 1 for prime p)"""
        # For prime p=7, any a^6 mod 7 should be 1 (if gcd(a,7)=1)
        result = modular_exponentiation(3, 6, 7)
        self.assertEqual(result, 1, "Fermat's Little Theorem failed for 3^6 mod 7")
    
    # TC12: Boundary - Base equals modulus
    def test_tc12_base_equals_modulus(self):
        """Test case TC12: b = m, result should be 0"""
        result = modular_exponentiation(7, 5, 7)
        self.assertEqual(result, 0, "7^5 mod 7 should be 0")
    
    # TC13: Boundary - Base greater than modulus
    def test_tc13_base_greater_than_modulus(self):
        """Test case TC13: b > m"""
        result = modular_exponentiation(10, 3, 7)
        expected = (10 ** 3) % 7
        self.assertEqual(result, expected, f"10^3 mod 7 should be {expected}")
    
    # TC14: Known cryptographic calculation
    def test_tc14_known_calculation(self):
        """Test case TC14: Known result - 7^26 mod 26"""
        result = modular_exponentiation(7, 26, 26)
        expected = pow(7, 26, 26)
        self.assertEqual(result, expected)
    
    # TC15: Power of 2 modulo power of 2
    def test_tc15_powers_of_two(self):
        """Test case TC15: 2^8 mod 2^5 = 0"""
        result = modular_exponentiation(2, 8, 32)
        self.assertEqual(result, 0, "2^8 mod 32 should be 0")


class TestModularExponentiationEdgeCases(unittest.TestCase):
    """Additional edge cases and correctness tests"""
    
    def test_consistency_with_builtin_pow(self):
        """Verify results match Python's built-in pow() for various inputs"""
        test_cases = [
            (2, 5, 13),
            (10, 20, 100),
            (7, 11, 19),
            (123, 456, 789),
            (999, 999, 997)
        ]
        
        for b, n, m in test_cases:
            result = modular_exponentiation(b, n, m)
            expected = pow(b, n, m)
            self.assertEqual(result, expected, 
                           f"Mismatch for {b}^{n} mod {m}")
    
    def test_negative_result_should_not_occur(self):
        """Ensure result is never negative"""
        test_cases = [
            (5, 10, 3),
            (100, 50, 7),
            (2, 100, 17)
        ]
        
        for b, n, m in test_cases:
            result = modular_exponentiation(b, n, m)
            self.assertGreaterEqual(result, 0, 
                                   f"Result should be non-negative for {b}^{n} mod {m}")
    
    def test_result_less_than_modulus(self):
        """Ensure result is always less than modulus"""
        test_cases = [
            (7, 15, 11),
            (20, 30, 19),
            (100, 200, 97)
        ]
        
        for b, n, m in test_cases:
            result = modular_exponentiation(b, n, m)
            self.assertLess(result, m, 
                          f"Result should be less than modulus for {b}^{n} mod {m}")


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestModularExponentiation))
    suite.addTest(unittest.makeSuite(TestModularExponentiationEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
