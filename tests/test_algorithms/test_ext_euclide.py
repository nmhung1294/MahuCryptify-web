"""
Unit Test for Ext_Euclide function - Black Box Testing
Module: MahuCrypt_app.cryptography.algos
Function: Ext_Euclide(a, b)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.algos import Ext_Euclide


class TestExtEuclide(unittest.TestCase):
    """
    Black Box Testing for Extended Euclidean Algorithm
    
    Test Plan:
    - PE1: Coprime numbers (GCD = 1)
    - PE2: Numbers with GCD > 1
    - PE3: One parameter is 0
    - PE4: Both parameters are 0
    - PE5: Negative numbers
    - PE6: Large numbers (performance test)
    - Boundary: Edge cases (0, 1, equal values)
    """
    
    def verify_extended_gcd(self, a, b, d, x, y):
        """
        Helper function to verify Bézout's identity: a*x + b*y = d
        where d = gcd(a, b)
        """
        return a * x + b * y == d
    
    # TC01: PE1 (Coprime - Nguyên tố cùng nhau)
    def test_tc01_coprime_numbers(self):
        """Test case TC01: Coprime numbers (7, 26)"""
        a, b = 7, 26
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 1
        self.assertEqual(d, 1, f"GCD of {a} and {b} should be 1")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC02: PE2 (GCD > 1)
    def test_tc02_gcd_greater_than_one(self):
        """Test case TC02: Numbers with GCD > 1 (12, 18)"""
        a, b = 12, 18
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 6
        self.assertEqual(d, 6, f"GCD of {a} and {b} should be 6")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC03: PE3 (b = 0)
    def test_tc03_b_equals_zero(self):
        """Test case TC03: b = 0, should handle division by zero (10, 0)"""
        a, b = 10, 0
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: (10, 1, 0)
        self.assertEqual(d, 10, f"GCD of {a} and {b} should be {a}")
        self.assertEqual(x, 1, f"x coefficient should be 1")
        self.assertEqual(y, 0, f"y coefficient should be 0")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC04: PE4 (a = 0)
    def test_tc04_a_equals_zero(self):
        """Test case TC04: a = 0 (0, 15)"""
        a, b = 0, 15
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: (15, 0, 1)
        self.assertEqual(d, 15, f"GCD of {a} and {b} should be {b}")
        self.assertEqual(x, 0, f"x coefficient should be 0")
        self.assertEqual(y, 1, f"y coefficient should be 1")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC05: Biên (0, 0) - Critical Case
    def test_tc05_both_zero(self):
        """Test case TC05: Both parameters are 0 (0, 0) - Critical Case"""
        a, b = 0, 0
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: (0, 0, 0) or implementation-specific behavior
        self.assertEqual(d, 0, f"GCD of {a} and {b} should be 0")
        
        # For (0, 0), Bézout's identity is trivially satisfied
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC06: PE5 (Số âm - a âm)
    def test_tc06_negative_a(self):
        """Test case TC06: Negative a (-12, 18)"""
        a, b = -12, 18
        d, x, y = Ext_Euclide(a, b)
        
        # GCD should be positive
        self.assertGreaterEqual(d, 0, "GCD should be non-negative")
        
        # Expected: GCD = 6
        self.assertEqual(abs(d), 6, f"Absolute GCD of {a} and {b} should be 6")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC07: PE6 (Cả 2 âm)
    def test_tc07_both_negative(self):
        """Test case TC07: Both negative (-12, -18)"""
        a, b = -12, -18
        d, x, y = Ext_Euclide(a, b)
        
        # GCD should be positive
        self.assertGreaterEqual(d, 0, "GCD should be non-negative")
        
        # Expected: GCD = 6
        self.assertEqual(abs(d), 6, f"Absolute GCD of {a} and {b} should be 6")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC08: Biên (Số nguyên tố lớn) - Performance Test
    def test_tc08_large_prime_numbers(self):
        """Test case TC08: Large prime numbers - Performance test"""
        # Two large primes (coprime)
        a, b = 1000000007, 1000000009
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 1 (primes are coprime)
        self.assertEqual(d, 1, f"GCD of large primes should be 1")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed for large numbers"
        )
    
    # TC09: PE7 (a = b)
    def test_tc09_equal_values(self):
        """Test case TC09: Equal values (15, 15)"""
        a, b = 15, 15
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 15
        self.assertEqual(d, 15, f"GCD of equal numbers should be the number itself")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC10: Biên (Số lớn với GCD > 1)
    def test_tc10_large_numbers_with_gcd(self):
        """Test case TC10: Large numbers with GCD > 1 (999999999, 333333333)"""
        a, b = 999999999, 333333333
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 333333333 (since 999999999 = 3 * 333333333)
        self.assertEqual(d, 333333333, f"GCD should be 333333333")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC11: PE8 (a = 1) - Biên nhỏ nhất dương
    def test_tc11_a_equals_one(self):
        """Test case TC11: a = 1 (1, 100)"""
        a, b = 1, 100
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 1
        self.assertEqual(d, 1, f"GCD of 1 and any number should be 1")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )
    
    # TC12: PE9 (b = 1) - Biên nhỏ nhất dương
    def test_tc12_b_equals_one(self):
        """Test case TC12: b = 1 (100, 1)"""
        a, b = 100, 1
        d, x, y = Ext_Euclide(a, b)
        
        # Expected: GCD = 1
        self.assertEqual(d, 1, f"GCD of any number and 1 should be 1")
        
        # Verify Bézout's identity
        self.assertTrue(
            self.verify_extended_gcd(a, b, d, x, y),
            f"Bézout's identity failed: {a}*{x} + {b}*{y} should equal {d}"
        )


class TestExtEuclideEdgeCases(unittest.TestCase):
    """Additional edge cases and stress tests"""
    
    def verify_extended_gcd(self, a, b, d, x, y):
        """Helper function to verify Bézout's identity"""
        return a * x + b * y == d
    
    def test_fibonacci_numbers(self):
        """Test with Fibonacci numbers (worst case for Euclidean algorithm)"""
        # Consecutive Fibonacci numbers are coprime
        a, b = 89, 144  # F(11), F(12)
        d, x, y = Ext_Euclide(a, b)
        
        self.assertEqual(d, 1, "Consecutive Fibonacci numbers should be coprime")
        self.assertTrue(self.verify_extended_gcd(a, b, d, x, y))
    
    def test_powers_of_two(self):
        """Test with powers of 2"""
        a, b = 64, 256  # 2^6, 2^8
        d, x, y = Ext_Euclide(a, b)
        
        self.assertEqual(d, 64, "GCD of 64 and 256 should be 64")
        self.assertTrue(self.verify_extended_gcd(a, b, d, x, y))
    
    def test_one_divides_other(self):
        """Test when one number divides the other"""
        a, b = 7, 49  # b = a * 7
        d, x, y = Ext_Euclide(a, b)
        
        self.assertEqual(d, 7, "GCD should be the smaller number")
        self.assertTrue(self.verify_extended_gcd(a, b, d, x, y))


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestExtEuclide))
    suite.addTest(unittest.makeSuite(TestExtEuclideEdgeCases))
    return suite


if __name__ == '__main__':
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
