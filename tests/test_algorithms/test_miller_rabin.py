"""
Unit Test for miller_rabin_test function - Black Box Testing
Module: MahuCrypt_app.cryptography.algos
Function: miller_rabin_test(n, k)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Test primality of number n with k iterations
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.algos import miller_rabin_test


class TestMillerRabinTest(unittest.TestCase):
    """
    Black Box Testing for Miller-Rabin Primality Test
    
    Test Plan:
    - PE1: Known primes (should return True)
    - PE2: Known composites (should return False)
    - PE3: Small numbers (2, 3)
    - PE4: Even numbers (should return False except 2)
    - PE5: Large primes
    - PE6: Carmichael numbers (pseudoprimes)
    - Boundary: 0, 1, negative numbers
    """
    
    # TC01: Small prime - 2
    def test_tc01_prime_two(self):
        """Test case TC01: 2 is prime"""
        result = miller_rabin_test(2, 10)
        self.assertTrue(result, "2 should be identified as prime")
    
    # TC02: Small prime - 3
    def test_tc02_prime_three(self):
        """Test case TC02: 3 is prime"""
        result = miller_rabin_test(3, 10)
        self.assertTrue(result, "3 should be identified as prime")
    
    # TC03: PE1 - Small known primes
    def test_tc03_small_primes(self):
        """Test case TC03: Small known primes (5, 7, 11, 13, 17, 19)"""
        small_primes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        
        for prime in small_primes:
            with self.subTest(prime=prime):
                result = miller_rabin_test(prime, 10)
                self.assertTrue(result, f"{prime} should be identified as prime")
    
    # TC04: PE2 - Small known composites
    def test_tc04_small_composites(self):
        """Test case TC04: Small known composite numbers"""
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21]
        
        for composite in composites:
            with self.subTest(composite=composite):
                result = miller_rabin_test(composite, 10)
                self.assertFalse(result, f"{composite} should be identified as composite")
    
    # TC05: PE4 - Even numbers (except 2)
    def test_tc05_even_numbers(self):
        """Test case TC05: Even numbers are not prime (except 2)"""
        even_numbers = [100, 1000, 10000, 123456]
        
        for num in even_numbers:
            with self.subTest(num=num):
                result = miller_rabin_test(num, 10)
                self.assertFalse(result, f"{num} should be identified as composite (even)")
    
    # TC06: Boundary - n = 0
    def test_tc06_zero(self):
        """Test case TC06: 0 is not prime"""
        result = miller_rabin_test(0, 10)
        self.assertFalse(result, "0 should not be identified as prime")
    
    # TC07: Boundary - n = 1
    def test_tc07_one(self):
        """Test case TC07: 1 is not prime"""
        result = miller_rabin_test(1, 10)
        self.assertFalse(result, "1 should not be identified as prime")
    
    # TC08: Boundary - Negative numbers
    def test_tc08_negative_numbers(self):
        """Test case TC08: Negative numbers are not prime"""
        result = miller_rabin_test(-5, 10)
        self.assertFalse(result, "Negative numbers should not be prime")
    
    # TC09: PE5 - Medium primes
    def test_tc09_medium_primes(self):
        """Test case TC09: Medium-sized known primes"""
        medium_primes = [97, 101, 103, 107, 109, 113, 127, 131, 137, 139]
        
        for prime in medium_primes:
            with self.subTest(prime=prime):
                result = miller_rabin_test(prime, 20)
                self.assertTrue(result, f"{prime} should be identified as prime")
    
    # TC10: PE5 - Large primes
    def test_tc10_large_primes(self):
        """Test case TC10: Large known primes"""
        large_primes = [
            1009,      # 4-digit prime
            10007,     # 5-digit prime
            100003,    # 6-digit prime
            1000003,   # 7-digit prime
        ]
        
        for prime in large_primes:
            with self.subTest(prime=prime):
                result = miller_rabin_test(prime, 100)
                self.assertTrue(result, f"{prime} should be identified as prime")
    
    # TC11: Large composite numbers
    def test_tc11_large_composites(self):
        """Test case TC11: Large composite numbers"""
        large_composites = [
            1000,      # 2^3 * 5^3
            10000,     # 2^4 * 5^4
            100000,    # 2^5 * 5^5
            999999,    # 3^3 * 7 * 11 * 13 * 37
        ]
        
        for composite in large_composites:
            with self.subTest(composite=composite):
                result = miller_rabin_test(composite, 100)
                self.assertFalse(result, f"{composite} should be identified as composite")
    
    # TC12: PE6 - Carmichael numbers (strong pseudoprimes)
    def test_tc12_carmichael_numbers(self):
        """Test case TC12: Carmichael numbers (should still be detected as composite)"""
        # 561 is the smallest Carmichael number (561 = 3 × 11 × 17)
        carmichael_numbers = [561, 1105, 1729]
        
        for num in carmichael_numbers:
            with self.subTest(num=num):
                result = miller_rabin_test(num, 100)
                self.assertFalse(result, 
                               f"Carmichael number {num} should be identified as composite")
    
    # TC13: Mersenne primes
    def test_tc13_mersenne_primes(self):
        """Test case TC13: Mersenne primes (2^p - 1)"""
        # 2^7 - 1 = 127 (prime)
        # 2^13 - 1 = 8191 (prime)
        mersenne_primes = [127, 8191]
        
        for prime in mersenne_primes:
            with self.subTest(prime=prime):
                result = miller_rabin_test(prime, 100)
                self.assertTrue(result, f"Mersenne prime {prime} should be identified as prime")
    
    # TC14: Semi-primes (product of two primes)
    def test_tc14_semiprimes(self):
        """Test case TC14: Semi-primes (product of two primes)"""
        semiprimes = [
            6,      # 2 × 3
            15,     # 3 × 5
            21,     # 3 × 7
            35,     # 5 × 7
            77,     # 7 × 11
            143,    # 11 × 13
        ]
        
        for semiprime in semiprimes:
            with self.subTest(semiprime=semiprime):
                result = miller_rabin_test(semiprime, 50)
                self.assertFalse(result, f"Semi-prime {semiprime} should be composite")
    
    # TC15: Different iteration counts
    def test_tc15_iteration_count_consistency(self):
        """Test case TC15: Results should be consistent across different k values"""
        test_number = 97  # Known prime
        
        # Test with different k values
        k_values = [5, 10, 20, 50, 100]
        results = [miller_rabin_test(test_number, k) for k in k_values]
        
        # All should return True for a prime
        self.assertTrue(all(results), 
                       "Prime should be identified correctly regardless of k value")


class TestMillerRabinTestEdgeCases(unittest.TestCase):
    """Additional edge cases and probabilistic behavior tests"""
    
    def test_very_large_prime(self):
        """Test with very large prime number"""
        # 1000000007 is a known prime
        large_prime = 1000000007
        result = miller_rabin_test(large_prime, 100)
        self.assertTrue(result, f"{large_prime} should be identified as prime")
    
    def test_very_large_composite(self):
        """Test with very large composite number"""
        # 1000000008 = 2^3 × 125000001
        large_composite = 1000000008
        result = miller_rabin_test(large_composite, 100)
        self.assertFalse(result, f"{large_composite} should be identified as composite")
    
    def test_powers_of_primes(self):
        """Test powers of prime numbers (should be composite except p^1)"""
        powers = [
            (2, 2, 4),
            (2, 3, 8),
            (3, 2, 9),
            (5, 2, 25),
            (7, 2, 49)
        ]
        
        for base, exp, value in powers:
            with self.subTest(value=value):
                result = miller_rabin_test(value, 50)
                self.assertFalse(result, 
                               f"{base}^{exp} = {value} should be composite")
    
    def test_consecutive_primes(self):
        """Test consecutive prime numbers"""
        # Twin primes
        twin_primes = [(3, 5), (5, 7), (11, 13), (17, 19), (29, 31), (41, 43)]
        
        for p1, p2 in twin_primes:
            with self.subTest(p1=p1, p2=p2):
                self.assertTrue(miller_rabin_test(p1, 50), f"{p1} should be prime")
                self.assertTrue(miller_rabin_test(p2, 50), f"{p2} should be prime")


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestMillerRabinTest))
    suite.addTest(unittest.makeSuite(TestMillerRabinTestEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
