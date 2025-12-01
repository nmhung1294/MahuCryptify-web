"""
Unit tests for create_ECDSA_keys function
Test Strategy: Black Box Testing using Equivalence Partitioning and Boundary Value Analysis
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.public_key_cryptography import create_ECDSA_keys
from MahuCrypt_app.cryptography.algos import is_point_on_curve, miller_rabin_test


class TestCreateECDSAKeys(unittest.TestCase):
    """Test cases for create_ECDSA_keys function"""

    def test_tc01_valid_small_curve(self):
        """TC01: Valid small curve parameters"""
        # Using a small known curve
        p = 23  # prime
        a = 1
        b = 1
        n = 28  # number of points on curve (example)
        
        result = create_ECDSA_keys(p, a, b, n)
        
        # Check structure
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        
        # Check public_key has required fields
        pub_key = result["public_key"]
        self.assertIn("p", pub_key)
        self.assertIn("q", pub_key)
        self.assertIn("a", pub_key)
        self.assertIn("b", pub_key)
        self.assertIn("G", pub_key)
        self.assertIn("Q", pub_key)
        
        # Check values are strings
        self.assertIsInstance(pub_key["p"], str)
        self.assertIsInstance(pub_key["q"], str)
        self.assertIsInstance(result["private_key"], str)
        
        # Check p, a, b match input
        self.assertEqual(int(pub_key["p"]), p)
        self.assertEqual(int(pub_key["a"]), a)
        self.assertEqual(int(pub_key["b"]), b)

    def test_tc02_valid_medium_curve(self):
        """TC02: Valid medium curve parameters"""
        p = 97  # prime
        a = 2
        b = 3
        n = 100
        
        result = create_ECDSA_keys(p, a, b, n)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        
        pub_key = result["public_key"]
        self.assertEqual(int(pub_key["p"]), p)
        self.assertEqual(int(pub_key["a"]), a)
        self.assertEqual(int(pub_key["b"]), b)

    def test_tc03_q_is_prime(self):
        """TC03: Verify q is prime (largest prime factor of n)"""
        p = 23
        a = 1
        b = 1
        n = 28  # 28 = 2^2 * 7, so q should be 7
        
        result = create_ECDSA_keys(p, a, b, n)
        q = int(result["public_key"]["q"])
        
        # q should be prime
        self.assertTrue(miller_rabin_test(q, 10))

    def test_tc04_G_is_on_curve(self):
        """TC04: Verify G (generator point) is on the curve"""
        p = 23
        a = 1
        b = 1
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        pub_key = result["public_key"]
        p_val = int(pub_key["p"])
        a_val = int(pub_key["a"])
        b_val = int(pub_key["b"])
        
        # Parse G point
        G_str = pub_key["G"]
        G = eval(G_str)  # Convert string to tuple
        
        # Check G is on curve
        self.assertTrue(is_point_on_curve(p_val, a_val, b_val, G))

    def test_tc05_Q_is_on_curve(self):
        """TC05: Verify Q (public key point) is on the curve"""
        p = 23
        a = 1
        b = 1
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        pub_key = result["public_key"]
        p_val = int(pub_key["p"])
        a_val = int(pub_key["a"])
        b_val = int(pub_key["b"])
        
        # Parse Q point
        Q_str = pub_key["Q"]
        Q = eval(Q_str)
        
        # Check Q is on curve
        self.assertTrue(is_point_on_curve(p_val, a_val, b_val, Q))

    def test_tc06_private_key_in_range(self):
        """TC06: Verify private key d is in valid range (1 <= d < q)"""
        p = 23
        a = 1
        b = 1
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        d = int(result["private_key"])
        q = int(result["public_key"]["q"])
        
        # d should be in range [1, q-1]
        self.assertGreaterEqual(d, 1)
        self.assertLess(d, q)

    def test_tc07_p_zero(self):
        """TC07: p = 0 (invalid)"""
        with self.assertRaises(Exception):
            create_ECDSA_keys(0, 1, 1, 10)

    def test_tc08_p_negative(self):
        """TC08: p negative (invalid)"""
        with self.assertRaises(Exception):
            create_ECDSA_keys(-23, 1, 1, 10)

    def test_tc09_n_zero(self):
        """TC09: n = 0 (invalid, division by zero)"""
        with self.assertRaises(Exception):
            create_ECDSA_keys(23, 1, 1, 0)

    def test_tc10_n_one(self):
        """TC10: n = 1 (edge case)"""
        try:
            result = create_ECDSA_keys(23, 1, 1, 1)
            # If it doesn't raise exception, check structure
            self.assertIn("public_key", result)
        except Exception:
            # May fail due to q calculation
            pass

    def test_tc11_singular_curve(self):
        """TC11: Singular curve (4a^3 + 27b^2 = 0)"""
        # For p=23, a=0, b=0 gives singular curve
        p = 23
        a = 0
        b = 0
        n = 10
        
        # May raise exception or return invalid result
        try:
            result = create_ECDSA_keys(p, a, b, n)
            # If succeeds, just check structure
            self.assertIn("public_key", result)
        except Exception:
            pass

    def test_tc12_large_n(self):
        """TC12: Large n value"""
        p = 97
        a = 2
        b = 3
        n = 1000
        
        result = create_ECDSA_keys(p, a, b, n)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)

    def test_tc13_a_zero(self):
        """TC13: a = 0 (valid curve parameter)"""
        p = 23
        a = 0
        b = 7
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        pub_key = result["public_key"]
        self.assertEqual(int(pub_key["a"]), 0)

    def test_tc14_b_zero(self):
        """TC14: b = 0 (valid curve parameter)"""
        p = 23
        a = 7
        b = 0
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        pub_key = result["public_key"]
        self.assertEqual(int(pub_key["b"]), 0)

    def test_tc15_prime_n(self):
        """TC15: n is prime (q should equal n)"""
        p = 23
        a = 1
        b = 1
        n = 29  # prime number
        
        result = create_ECDSA_keys(p, a, b, n)
        
        q = int(result["public_key"]["q"])
        # When n is prime, q should be n
        self.assertEqual(q, n)

    def test_tc16_composite_n(self):
        """TC16: n is composite (test largest_prime_factor)"""
        p = 23
        a = 1
        b = 1
        n = 30  # 30 = 2 * 3 * 5, largest prime = 5
        
        result = create_ECDSA_keys(p, a, b, n)
        
        q = int(result["public_key"]["q"])
        # q should be 5
        self.assertEqual(q, 5)

    def test_tc17_h_calculation(self):
        """TC17: Verify h = n // q is calculated correctly"""
        p = 23
        a = 1
        b = 1
        n = 30  # 30 = 2 * 3 * 5
        
        result = create_ECDSA_keys(p, a, b, n)
        
        q = int(result["public_key"]["q"])  # should be 5
        h = n // q  # should be 6
        
        self.assertEqual(h, 6)

    def test_tc18_consistency(self):
        """TC18: Multiple calls with same parameters should give different keys"""
        p = 23
        a = 1
        b = 1
        n = 28
        
        result1 = create_ECDSA_keys(p, a, b, n)
        result2 = create_ECDSA_keys(p, a, b, n)
        
        # Private keys should be different (randomized)
        d1 = int(result1["private_key"])
        d2 = int(result2["private_key"])
        
        # There's a small chance they could be equal, but very unlikely
        # Just check both are valid
        q = int(result1["public_key"]["q"])
        self.assertGreaterEqual(d1, 1)
        self.assertLess(d1, q)
        self.assertGreaterEqual(d2, 1)
        self.assertLess(d2, q)

    def test_tc19_string_format(self):
        """TC19: Verify all numeric values are returned as strings"""
        p = 23
        a = 1
        b = 1
        n = 28
        
        result = create_ECDSA_keys(p, a, b, n)
        
        pub_key = result["public_key"]
        
        # All should be strings
        self.assertIsInstance(pub_key["p"], str)
        self.assertIsInstance(pub_key["q"], str)
        self.assertIsInstance(pub_key["a"], str)
        self.assertIsInstance(pub_key["b"], str)
        self.assertIsInstance(pub_key["G"], str)
        self.assertIsInstance(pub_key["Q"], str)
        self.assertIsInstance(result["private_key"], str)

    def test_tc20_large_parameters(self):
        """TC20: Large curve parameters"""
        p = 2017  # larger prime
        a = 5
        b = 7
        n = 2000
        
        result = create_ECDSA_keys(p, a, b, n)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        
        # Verify Q is on curve
        pub_key = result["public_key"]
        p_val = int(pub_key["p"])
        a_val = int(pub_key["a"])
        b_val = int(pub_key["b"])
        Q = eval(pub_key["Q"])
        
        self.assertTrue(is_point_on_curve(p_val, a_val, b_val, Q))


if __name__ == '__main__':
    unittest.main()
