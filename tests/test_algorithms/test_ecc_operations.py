"""
Unit Test for ECC Point Operations - Black Box Testing
Module: MahuCrypt_app.cryptography.algos
Functions: double(point, a, p), add_points(point1, point2, a, p), double_and_add(point, n, a, p)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Test Elliptic Curve Cryptography point arithmetic
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.algos import double, add_points, double_and_add


class TestDoublePoint(unittest.TestCase):
    """
    Black Box Testing for double(point, a, p)
    Doubles a point on elliptic curve y^2 = x^3 + ax + b (mod p)
    
    Test Plan:
    - PE1: Normal point doubling
    - PE2: Point at infinity (0, 0)
    - PE3: Point with y = 0
    - PE4: Different curve parameters
    - Boundary: Edge cases
    """
    
    # TC01: PE1 - Normal point doubling
    def test_tc01_normal_point_doubling(self):
        """Test case TC01: Double a normal point on curve y^2 = x^3 + 2x + 3 (mod 97)"""
        point = (3, 6)
        a = 2
        p = 97
        result = double(point, a, p)
        
        # Verify result is a tuple
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        
        # Verify point is on curve (if not point at infinity)
        if result != (0, 0):
            x, y = result
            self.assertEqual((y**2) % p, (x**3 + a*x + 3) % p, 
                           "Result point should be on the curve")
    
    # TC02: PE2 - Point at infinity (0, 0)
    def test_tc02_point_at_infinity(self):
        """Test case TC02: Doubling point at infinity returns point at infinity"""
        point = (0, 0)
        a = 2
        p = 97
        result = double(point, a, p)
        
        self.assertEqual(result, (0, 0), 
                        "Doubling point at infinity should return point at infinity")
    
    # TC03: PE3 - Point with y = 0
    def test_tc03_point_with_y_zero(self):
        """Test case TC03: Point with y=0 (vertical tangent)"""
        # For curve y^2 = x^3 + ax + b, if y=0, then x^3 + ax + b = 0
        # This is a special case where doubling returns point at infinity
        a = 1
        p = 7
        # Find a point with y=0 if possible, or test the behavior
        # For simplicity, test that function handles this case
        point = (0, 0)  # This will trigger the y=0 condition in double()
        result = double(point, a, p)
        self.assertEqual(result, (0, 0))
    
    # TC04: PE4 - Different curve parameters
    def test_tc04_different_curves(self):
        """Test case TC04: Test with different curve parameters"""
        test_cases = [
            ((5, 1), 1, 23),
            ((3, 10), 4, 11),
            ((2, 5), 3, 13),
        ]
        
        for point, a, p in test_cases:
            with self.subTest(point=point, a=a, p=p):
                result = double(point, a, p)
                self.assertIsInstance(result, tuple)
                self.assertEqual(len(result), 2)
    
    # TC05: Boundary - Small prime
    def test_tc05_small_prime(self):
        """Test case TC05: Test with small prime p=5"""
        point = (1, 2)
        a = 1
        p = 5
        result = double(point, a, p)
        
        # Result should have coordinates in [0, p)
        if result != (0, 0):
            x, y = result
            self.assertGreaterEqual(x, 0)
            self.assertLess(x, p)
            self.assertGreaterEqual(y, 0)
            self.assertLess(y, p)
    
    # TC06: Boundary - Large prime
    def test_tc06_large_prime(self):
        """Test case TC06: Test with larger prime"""
        point = (10, 15)
        a = 5
        p = 1009  # Larger prime
        result = double(point, a, p)
        
        self.assertIsInstance(result, tuple)
        if result != (0, 0):
            x, y = result
            self.assertLess(x, p)
            self.assertLess(y, p)


class TestAddPoints(unittest.TestCase):
    """
    Black Box Testing for add_points(point1, point2, a, p)
    Adds two points on elliptic curve
    
    Test Plan:
    - PE1: Adding two different points
    - PE2: Adding point to itself (should use doubling)
    - PE3: Adding point to point at infinity
    - PE4: Adding inverse points (x same, y opposite)
    - Boundary: Edge cases
    """
    
    # TC07: PE1 - Adding two different points
    def test_tc07_add_different_points(self):
        """Test case TC07: Add two different points"""
        point1 = (3, 6)
        point2 = (4, 7)
        a = 2
        p = 97
        result = add_points(point1, point2, a, p)
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
    
    # TC08: PE2 - Adding point to itself
    def test_tc08_add_point_to_itself(self):
        """Test case TC08: Adding point to itself should use doubling"""
        point = (3, 6)
        a = 2
        p = 97
        result_add = add_points(point, point, a, p)
        result_double = double(point, a, p)
        
        self.assertEqual(result_add, result_double, 
                        "Adding point to itself should equal doubling")
    
    # TC09: PE3 - Adding point to point at infinity
    def test_tc09_add_point_to_infinity(self):
        """Test case TC09: P + O = P (identity element)"""
        point = (3, 6)
        infinity = (0, 0)
        a = 2
        p = 97
        
        result1 = add_points(point, infinity, a, p)
        result2 = add_points(infinity, point, a, p)
        
        self.assertEqual(result1, point, "P + O should equal P")
        self.assertEqual(result2, point, "O + P should equal P")
    
    # TC10: PE4 - Adding inverse points (vertical line)
    def test_tc10_add_inverse_points(self):
        """Test case TC10: Adding inverse points returns point at infinity"""
        point1 = (3, 6)
        point2 = (3, 97-6)  # Inverse point (same x, opposite y mod p)
        a = 2
        p = 97
        result = add_points(point1, point2, a, p)
        
        self.assertEqual(result, (0, 0), 
                        "Adding inverse points should return point at infinity")
    
    # TC11: Commutativity test
    def test_tc11_commutativity(self):
        """Test case TC11: P1 + P2 = P2 + P1 (commutative property)"""
        point1 = (3, 6)
        point2 = (4, 7)
        a = 2
        p = 97
        
        result1 = add_points(point1, point2, a, p)
        result2 = add_points(point2, point1, a, p)
        
        self.assertEqual(result1, result2, 
                        "Point addition should be commutative")
    
    # TC12: Associativity test
    def test_tc12_associativity(self):
        """Test case TC12: (P1 + P2) + P3 = P1 + (P2 + P3)"""
        point1 = (3, 6)
        point2 = (4, 7)
        point3 = (5, 8)
        a = 2
        p = 97
        
        # (P1 + P2) + P3
        temp1 = add_points(point1, point2, a, p)
        result1 = add_points(temp1, point3, a, p)
        
        # P1 + (P2 + P3)
        temp2 = add_points(point2, point3, a, p)
        result2 = add_points(point1, temp2, a, p)
        
        self.assertEqual(result1, result2, 
                        "Point addition should be associative")
    
    # TC13: Identity element test
    def test_tc13_identity_element(self):
        """Test case TC13: Adding point at infinity twice"""
        infinity = (0, 0)
        a = 2
        p = 97
        result = add_points(infinity, infinity, a, p)
        
        self.assertEqual(result, (0, 0), 
                        "O + O should equal O")


class TestDoubleAndAdd(unittest.TestCase):
    """
    Black Box Testing for double_and_add(point, n, a, p)
    Scalar multiplication: n * P
    
    Test Plan:
    - PE1: n = 0 (should return point at infinity)
    - PE2: n = 1 (should return point itself)
    - PE3: n = 2 (should equal doubling)
    - PE4: Large n
    - Boundary: Edge cases
    """
    
    # TC14: PE1 - Scalar multiplication by 0
    def test_tc14_multiply_by_zero(self):
        """Test case TC14: 0 * P = O (point at infinity)"""
        point = (3, 6)
        n = 0
        a = 2
        p = 97
        result = double_and_add(point, n, a, p)
        
        self.assertEqual(result, (0, 0), 
                        "Multiplying by 0 should return point at infinity")
    
    # TC15: PE2 - Scalar multiplication by 1
    def test_tc15_multiply_by_one(self):
        """Test case TC15: 1 * P = P"""
        point = (3, 6)
        n = 1
        a = 2
        p = 97
        result = double_and_add(point, n, a, p)
        
        self.assertEqual(result, point, 
                        "Multiplying by 1 should return the point itself")
    
    # TC16: PE3 - Scalar multiplication by 2
    def test_tc16_multiply_by_two(self):
        """Test case TC16: 2 * P should equal double(P)"""
        point = (3, 6)
        n = 2
        a = 2
        p = 97
        result_multiply = double_and_add(point, n, a, p)
        result_double = double(point, a, p)
        
        self.assertEqual(result_multiply, result_double, 
                        "2 * P should equal double(P)")
    
    # TC17: Scalar multiplication by 3
    def test_tc17_multiply_by_three(self):
        """Test case TC17: 3 * P = 2 * P + P"""
        point = (3, 6)
        n = 3
        a = 2
        p = 97
        
        result_multiply = double_and_add(point, n, a, p)
        
        # Manual calculation: 2P + P
        double_p = double(point, a, p)
        result_manual = add_points(double_p, point, a, p)
        
        self.assertEqual(result_multiply, result_manual, 
                        "3 * P should equal 2*P + P")
    
    # TC18: PE4 - Large scalar
    def test_tc18_large_scalar(self):
        """Test case TC18: Large scalar multiplication"""
        point = (3, 6)
        n = 100
        a = 2
        p = 97
        result = double_and_add(point, n, a, p)
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
    
    # TC19: Consistency check
    def test_tc19_consistency_check(self):
        """Test case TC19: n*P calculated multiple ways should match"""
        point = (3, 6)
        n = 5
        a = 2
        p = 97
        
        # Method 1: double_and_add
        result1 = double_and_add(point, n, a, p)
        
        # Method 2: repeated addition
        result2 = (0, 0)  # Start with infinity
        for _ in range(n):
            result2 = add_points(result2, point, a, p)
        
        self.assertEqual(result1, result2, 
                        "Different methods should give same result")
    
    # TC20: Point at infinity with scalar
    def test_tc20_infinity_with_scalar(self):
        """Test case TC20: n * O = O for any n"""
        infinity = (0, 0)
        n = 10
        a = 2
        p = 97
        result = double_and_add(infinity, n, a, p)
        
        self.assertEqual(result, (0, 0), 
                        "Multiplying point at infinity should return infinity")
    
    # TC21: Distributive property
    def test_tc21_distributive_property(self):
        """Test case TC21: (n1 + n2)*P = n1*P + n2*P"""
        point = (3, 6)
        n1 = 3
        n2 = 4
        a = 2
        p = 97
        
        # (n1 + n2) * P
        result1 = double_and_add(point, n1 + n2, a, p)
        
        # n1*P + n2*P
        temp1 = double_and_add(point, n1, a, p)
        temp2 = double_and_add(point, n2, a, p)
        result2 = add_points(temp1, temp2, a, p)
        
        self.assertEqual(result1, result2, 
                        "Distributive property should hold")
    
    # TC22: Power of 2 scalar
    def test_tc22_power_of_two_scalar(self):
        """Test case TC22: 2^k * P"""
        point = (3, 6)
        k = 4
        n = 2 ** k  # 16
        a = 2
        p = 97
        result = double_and_add(point, n, a, p)
        
        # Alternative: double k times
        temp = point
        for _ in range(k):
            temp = double(temp, a, p)
        
        self.assertEqual(result, temp, 
                        "2^k * P should equal k successive doublings")


class TestECCEdgeCases(unittest.TestCase):
    """Additional edge cases for ECC operations"""
    
    def test_large_prime_operations(self):
        """Test with larger prime for realistic cryptographic use"""
        # Use a larger prime
        p = 1009
        a = 5
        point = (100, 200)
        
        # Test doubling
        result_double = double(point, a, p)
        self.assertIsInstance(result_double, tuple)
        
        # Test addition
        point2 = (150, 250)
        result_add = add_points(point, point2, a, p)
        self.assertIsInstance(result_add, tuple)
        
        # Test scalar multiplication
        result_scalar = double_and_add(point, 10, a, p)
        self.assertIsInstance(result_scalar, tuple)
    
    def test_negative_coordinates_handling(self):
        """Test that modular arithmetic handles coordinates correctly"""
        # Coordinates should always be in [0, p)
        point = (3, 6)
        a = 2
        p = 97
        
        # Multiple operations
        result = double(point, a, p)
        result = add_points(result, point, a, p)
        result = double_and_add(point, 7, a, p)
        
        if result != (0, 0):
            x, y = result
            self.assertGreaterEqual(x, 0)
            self.assertLess(x, p)
            self.assertGreaterEqual(y, 0)
            self.assertLess(y, p)


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestDoublePoint))
    suite.addTest(unittest.makeSuite(TestAddPoints))
    suite.addTest(unittest.makeSuite(TestDoubleAndAdd))
    suite.addTest(unittest.makeSuite(TestECCEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
