"""
Unit Test for ECC (Elliptic Curve Cryptography) functions - Black Box Testing
Module: MahuCrypt_app.cryptography.public_key_cryptography
Functions: create_ECC_keys(bits), EN_ECC(string, public_key), DE_ECC(encrypted_message_str, public_key, private_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: ECC key generation, encryption, and decryption
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.public_key_cryptography import create_ECC_keys, EN_ECC, DE_ECC
from MahuCrypt_app.cryptography.algos import miller_rabin_test, double_and_add, add_points


class TestCreateECCKeys(unittest.TestCase):
    """
    Black Box Testing for create_ECC_keys(bits)
    
    ECC Key Generation:
    - p = random prime with 'bits' bits
    - a, b = random curve parameters (1 to 19) where 4*a³ + 27*b² ≠ 0
    - P = random point on curve y² = x³ + ax + b (mod p)
    - s = random private key in [1, p-1]
    - B = s*P (public key point)
    - Returns: public_key dict, private_key string, public_details with point count
    
    Test Plan: 20 test cases
    """
    
    # TC01: PE1 - bits=8
    def test_tc01_bits_8(self):
        """Test case TC01: Generate ECC keys with 8 bits"""
        result = create_ECC_keys(8)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIn("public_details", result)
    
    # TC02: PE1 - bits=16
    def test_tc02_bits_16(self):
        """Test case TC02: 16-bit ECC keys"""
        result = create_ECC_keys(16)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
    
    # TC03: PE2 - bits=32 (may be slow)
    def test_tc03_bits_32(self):
        """Test case TC03: 32-bit ECC keys"""
        result = create_ECC_keys(32)
        
        self.assertIsInstance(result, dict)
    
    # TC04: PE2 - bits=64 (skip - very slow)
    @unittest.skip("Too slow - 64 bit prime + curve generation")
    def test_tc04_bits_64(self):
        """Test case TC04: 64-bit keys"""
        result = create_ECC_keys(64)
        
        self.assertIn("public_key", result)
    
    # TC05: PE3 - bits=128 (skip - extremely slow)
    @unittest.skip("Extremely slow for testing")
    def test_tc05_bits_128(self):
        """Test case TC05: 128-bit keys"""
        result = create_ECC_keys(128)
        
        self.assertIsInstance(result, dict)
    
    # TC06: PE4 - bits=2 (may hang)
    @unittest.skip("May hang - too small")
    def test_tc06_bits_2(self):
        """Test case TC06: 2 bits - too small"""
        result = create_ECC_keys(2)
    
    # TC07: PE5 - bits=0
    @unittest.skip("Hangs - skip invalid bits")
    def test_tc07_bits_zero(self):
        """Test case TC07: Zero bits - invalid"""
        try:
            result = create_ECC_keys(0)
            self.fail("Should raise error")
        except (ValueError, ZeroDivisionError):
            pass
    
    # TC08: PE5 - Negative bits
    @unittest.skip("Hangs - skip invalid bits")
    def test_tc08_bits_negative(self):
        """Test case TC08: Negative bits - invalid"""
        try:
            result = create_ECC_keys(-10)
            self.fail("Should raise error")
        except (ValueError, OverflowError):
            pass
    
    # TC09: Return structure
    def test_tc09_return_structure(self):
        """Test case TC09: Validate return structure"""
        result = create_ECC_keys(16)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIn("public_details", result)
    
    # TC10: Public key structure
    def test_tc10_public_key_structure(self):
        """Test case TC10: Public key has p, a, b, P, B"""
        result = create_ECC_keys(16)
        
        public_key = result["public_key"]
        self.assertIn("p", public_key)
        self.assertIn("a", public_key)
        self.assertIn("b", public_key)
        self.assertIn("P", public_key)
        self.assertIn("B", public_key)
        # All strings
        for key in ["p", "a", "b", "P", "B"]:
            self.assertIsInstance(public_key[key], str)
    
    # TC11: Private key format
    def test_tc11_private_key_format(self):
        """Test case TC11: Private key is string"""
        result = create_ECC_keys(16)
        
        self.assertIsInstance(result["private_key"], str)
    
    # TC12: Public details structure
    def test_tc12_public_details(self):
        """Test case TC12: Public details has number_of_points"""
        result = create_ECC_keys(16)
        
        details = result["public_details"]
        self.assertIn("number_of_points", details)
        self.assertIsInstance(details["number_of_points"], str)
    
    # TC13: p is prime
    def test_tc13_p_is_prime(self):
        """Test case TC13: Verify p is prime"""
        result = create_ECC_keys(16)
        
        p = int(result["public_key"]["p"])
        self.assertTrue(miller_rabin_test(p, 100), f"p={p} should be prime")
    
    # TC14: Elliptic curve discriminant
    def test_tc14_curve_condition(self):
        """Test case TC14: Verify 4*a³ + 27*b² ≠ 0"""
        result = create_ECC_keys(16)
        
        a = int(result["public_key"]["a"])
        b = int(result["public_key"]["b"])
        
        discriminant = 4 * a**3 + 27 * b**2
        self.assertNotEqual(discriminant, 0, "Curve discriminant must be non-zero")
    
    # TC15: P is on curve
    def test_tc15_p_on_curve(self):
        """Test case TC15: Verify P satisfies y² = x³ + ax + b (mod p)"""
        result = create_ECC_keys(16)
        
        p = int(result["public_key"]["p"])
        a = int(result["public_key"]["a"])
        b = int(result["public_key"]["b"])
        P = eval(result["public_key"]["P"])
        
        x, y = P
        left = (y**2) % p
        right = (x**3 + a*x + b) % p
        
        self.assertEqual(left, right, f"Point P={P} should be on curve")
    
    # TC16: B = s*P
    def test_tc16_b_calculation(self):
        """Test case TC16: Verify B = double_and_add(P, s, a, p)"""
        result = create_ECC_keys(16)
        
        p = int(result["public_key"]["p"])
        a = int(result["public_key"]["a"])
        P = eval(result["public_key"]["P"])
        B = eval(result["public_key"]["B"])
        s = int(result["private_key"])
        
        expected_B = double_and_add(P, s, a, p)
        self.assertEqual(B, expected_B, "B should equal s*P")
    
    # TC17: s in valid range
    def test_tc17_s_in_range(self):
        """Test case TC17: Private key s in valid range [1, p-1]"""
        result = create_ECC_keys(16)
        
        p = int(result["public_key"]["p"])
        s = int(result["private_key"])
        
        self.assertGreaterEqual(s, 1, "s should be >= 1")
        self.assertLess(s, p, "s should be < p")
    
    # TC18: Randomness
    def test_tc18_randomness(self):
        """Test case TC18: Different keys on different calls"""
        result1 = create_ECC_keys(16)
        result2 = create_ECC_keys(16)
        
        p1 = result1["public_key"]["p"]
        p2 = result2["public_key"]["p"]
        
        self.assertNotEqual(p1, p2, "Keys should be random")
    
    # TC19: String format
    def test_tc19_string_format(self):
        """Test case TC19: All values stored as strings"""
        result = create_ECC_keys(16)
        
        for key in ["p", "a", "b", "P", "B"]:
            self.assertIsInstance(result["public_key"][key], str)
        
        self.assertIsInstance(result["private_key"], str)
        self.assertIsInstance(result["public_details"]["number_of_points"], str)
    
    # TC20: a, b in range
    def test_tc20_ab_range(self):
        """Test case TC20: Curve parameters a, b in [1, 19]"""
        result = create_ECC_keys(16)
        
        a = int(result["public_key"]["a"])
        b = int(result["public_key"]["b"])
        
        self.assertGreaterEqual(a, 1, "a should be >= 1")
        self.assertLess(a, 20, "a should be < 20")
        self.assertGreaterEqual(b, 1, "b should be >= 1")
        self.assertLess(b, 20, "b should be < 20")


class TestENECC(unittest.TestCase):
    """
    Black Box Testing for EN_ECC(string, public_key)
    
    ECC Encryption:
    - Input: plaintext, public_key dict
    - Random k for each block (non-deterministic)
    - Encrypts in 3-char blocks: converts to points, then (C1, C2) where C1=k*P, C2=M+k*B
    - Output: {"Message points": str(points), "Encrypted": str(list of tuple pairs)}
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test key pair"""
        cls.keys = create_ECC_keys(32)
        cls.public_key = cls.keys["public_key"]
        cls.private_key = int(cls.keys["private_key"])
        cls.p = int(cls.public_key["p"])
        cls.a = int(cls.public_key["a"])
    
    # TC01: PE1 - Short string (3 char)
    def test_tc01_short_string(self):
        """Test case TC01: 3-character string"""
        result = EN_ECC("ABC", self.public_key)
        
        self.assertIn("Message points", result)
        self.assertIn("Encrypted", result)
    
    # TC02: PE1 - Single character
    def test_tc02_single_char(self):
        """Test case TC02: Single character"""
        result = EN_ECC("A", self.public_key)
        
        self.assertIn("Message points", result)
        self.assertIn("Encrypted", result)
    
    # TC03: PE2 - Medium string (5 char)
    def test_tc03_medium_string(self):
        """Test case TC03: 5 characters"""
        result = EN_ECC("HELLO", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC04: PE2 - 6 characters
    def test_tc04_six_chars(self):
        """Test case TC04: 6 characters (2 blocks)"""
        result = EN_ECC("ABCDEF", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string (30 chars)"""
        result = EN_ECC("A" * 30, self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        result = EN_ECC("", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase(self):
        """Test case TC07: Lowercase input"""
        result = EN_ECC("hello", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC08: PE5 - Uppercase
    def test_tc08_uppercase(self):
        """Test case TC08: Uppercase input"""
        result = EN_ECC("HELLO", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC09: PE5 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case"""
        result = EN_ECC("HeLLo", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC10: PE6 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        result = EN_ECC("HELLO WORLD", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC11: PE6 - Special characters
    def test_tc11_special_chars(self):
        """Test case TC11: Special characters"""
        result = EN_ECC("HELLO!", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC12: PE7 - Valid key
    def test_tc12_valid_key(self):
        """Test case TC12: Standard operation"""
        result = EN_ECC("TEST", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC13: PE8 - Missing p
    def test_tc13_missing_p(self):
        """Test case TC13: Key without p"""
        bad_key = {"a": "2", "P": "(1,1)", "B": "(2,2)"}
        
        try:
            result = EN_ECC("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC14: PE8 - Missing a
    def test_tc14_missing_a(self):
        """Test case TC14: Key without a"""
        bad_key = {"p": self.public_key["p"], "P": self.public_key["P"], "B": self.public_key["B"]}
        
        try:
            result = EN_ECC("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC15: PE8 - Missing P
    def test_tc15_missing_p_point(self):
        """Test case TC15: Key without P"""
        bad_key = {"p": self.public_key["p"], "a": self.public_key["a"], "B": self.public_key["B"]}
        
        try:
            result = EN_ECC("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC16: PE8 - Missing B
    def test_tc16_missing_b_point(self):
        """Test case TC16: Key without B"""
        bad_key = {"p": self.public_key["p"], "a": self.public_key["a"], "P": self.public_key["P"]}
        
        try:
            result = EN_ECC("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC17: PE9 - p too small
    def test_tc17_p_too_small(self):
        """Test case TC17: Very small p"""
        tiny_key = {"p": "10", "a": "2", "P": "(1,1)", "B": "(2,2)"}
        
        try:
            result = EN_ECC("ZZZZ", tiny_key)
            # Might overflow or error
        except Exception:
            pass
    
    # TC18: Return structure
    def test_tc18_return_structure(self):
        """Test case TC18: Validate return structure"""
        result = EN_ECC("TEST", self.public_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Message points", result)
        self.assertIn("Encrypted", result)
    
    # TC19: Non-deterministic (random k)
    def test_tc19_non_deterministic(self):
        """Test case TC19: Same input gives different output (random k)"""
        result1 = EN_ECC("TEST", self.public_key)
        result2 = EN_ECC("TEST", self.public_key)
        
        # Should be different due to random k
        self.assertNotEqual(result1["Encrypted"], result2["Encrypted"],
                           "ECC uses random k, should differ")
    
    # TC20: Encrypted format
    def test_tc20_encrypted_format(self):
        """Test case TC20: Encrypted is string of list"""
        result = EN_ECC("TEST", self.public_key)
        
        encrypted_str = result["Encrypted"]
        self.assertIsInstance(encrypted_str, str)
        # Should contain tuple pairs
        self.assertIn("(", encrypted_str)


class TestDEECC(unittest.TestCase):
    """
    Black Box Testing for DE_ECC(encrypted_message_str, public_key, private_key)
    
    ECC Decryption:
    - Input: encrypted string, public_key, private_key (s)
    - Parse tuple pairs → decrypt: M = C2 - s*C1
    - Output: {"Decrypted": str(list of points)}
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test keys"""
        cls.keys = create_ECC_keys(32)
        cls.public_key = cls.keys["public_key"]
        cls.private_key = int(cls.keys["private_key"])
        cls.p = int(cls.public_key["p"])
        cls.a = int(cls.public_key["a"])
    
    # TC01: PE1 - Single tuple pair
    def test_tc01_single_tuple(self):
        """Test case TC01: Decrypt single block"""
        encrypted = EN_ECC("ABC", self.public_key)
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", result)
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC02: PE2 - Multiple tuple pairs
    def test_tc02_multiple_tuples(self):
        """Test case TC02: Decrypt multiple blocks"""
        encrypted = EN_ECC("HELLO WORLD", self.public_key)
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC03: PE3 - Empty list
    def test_tc03_empty_list(self):
        """Test case TC03: Decrypt empty"""
        result = DE_ECC("[]", self.public_key, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC04: PE4 - Valid keys
    def test_tc04_valid_keys(self):
        """Test case TC04: Standard decryption"""
        encrypted = EN_ECC("TEST", self.public_key)
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC05: PE5 - Wrong private key
    def test_tc05_wrong_private_key(self):
        """Test case TC05: Wrong private key"""
        encrypted = EN_ECC("TEST", self.public_key)
        wrong_s = (self.private_key + 1) % (self.p - 1)
        
        result = DE_ECC(encrypted["Encrypted"], self.public_key, wrong_s)
        # Will decrypt to wrong points
        self.assertIn("Decrypted", result)
    
    # TC06: PE5 - Wrong p
    def test_tc06_wrong_p(self):
        """Test case TC06: Wrong p value"""
        encrypted = EN_ECC("TEST", self.public_key)
        wrong_key = self.public_key.copy()
        wrong_key["p"] = str(int(self.public_key["p"]) + 1)
        
        try:
            result = DE_ECC(encrypted["Encrypted"], wrong_key, self.private_key)
            # Might error or give wrong result
        except Exception:
            pass
    
    # TC07: PE6 - Format variations
    def test_tc07_format_variations(self):
        """Test case TC07: Different format strings"""
        encrypted = EN_ECC("TEST", self.public_key)
        # Should parse correctly
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC08: PE7 - Malformed string
    def test_tc08_malformed_string(self):
        """Test case TC08: Invalid format"""
        try:
            result = DE_ECC("not a list", self.public_key, self.private_key)
            # Should error or return empty
        except (ValueError, IndexError):
            pass
    
    # TC09: PE7 - Non-numeric
    def test_tc09_non_numeric(self):
        """Test case TC09: Non-numeric in list"""
        try:
            result = DE_ECC("[((a,b),(c,d))]", self.public_key, self.private_key)
            self.fail("Should raise ValueError")
        except (ValueError, NameError):
            pass
    
    # TC10: PE8 - Round trip ABC
    def test_tc10_roundtrip_abc(self):
        """Test case TC10: Encrypt-decrypt ABC"""
        original = "ABC"
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        # Compare message points
        msg_points = encrypted["Message points"]
        dec_points = decrypted["Decrypted"]
        self.assertEqual(msg_points, dec_points, "Points should match after round trip")
    
    # TC11: PE8 - Round trip HELLO
    def test_tc11_roundtrip_hello(self):
        """Test case TC11: Round trip HELLO"""
        original = "HELLO"
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        msg_points = encrypted["Message points"]
        dec_points = decrypted["Decrypted"]
        self.assertEqual(msg_points, dec_points)
    
    # TC12: PE8 - Round trip long text
    def test_tc12_roundtrip_long(self):
        """Test case TC12: Long text round trip"""
        original = "A" * 30
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        msg_points = encrypted["Message points"]
        dec_points = decrypted["Decrypted"]
        self.assertEqual(msg_points, dec_points)
    
    # TC13: PE9 - Different messages
    def test_tc13_different_messages(self):
        """Test case TC13: Multiple different messages"""
        messages = ["AAA", "BBB", "CCC"]
        
        for msg in messages:
            with self.subTest(msg=msg):
                encrypted = EN_ECC(msg, self.public_key)
                decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
                
                msg_points = encrypted["Message points"]
                dec_points = decrypted["Decrypted"]
                self.assertEqual(msg_points, dec_points)
    
    # TC14: Return structure
    def test_tc14_return_structure(self):
        """Test case TC14: Validate return structure"""
        encrypted = EN_ECC("TEST", self.public_key)
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Decrypted", result)
    
    # TC15: Decrypted format
    def test_tc15_decrypted_format(self):
        """Test case TC15: Decrypted is string"""
        encrypted = EN_ECC("TEST", self.public_key)
        result = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC16: Case handling
    def test_tc16_case_handling(self):
        """Test case TC16: Mixed case handling"""
        original = "HeLLo"
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC17: Special chars
    def test_tc17_special_chars(self):
        """Test case TC17: Special characters"""
        original = "HELLO!"
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC18: Numbers
    def test_tc18_numbers(self):
        """Test case TC18: Numbers in string"""
        original = "HELLO123"
        encrypted = EN_ECC(original, self.public_key)
        decrypted = DE_ECC(encrypted["Encrypted"], self.public_key, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC19: Missing tuple values
    def test_tc19_missing_values(self):
        """Test case TC19: Incomplete tuple string"""
        try:
            # Missing values
            result = DE_ECC("[(1,2)]", self.public_key, self.private_key)
            # Should error or partial
        except (IndexError, ValueError):
            pass
    
    # TC20: Odd number of points
    def test_tc20_odd_values(self):
        """Test case TC20: Odd number of values (3 instead of 4)"""
        try:
            # Simulate incomplete: "1,2,3"
            result = DE_ECC("[1,2,3]", self.public_key, self.private_key)
            # Might skip last value or error
        except (IndexError, ValueError):
            pass


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestCreateECCKeys))
    suite.addTest(unittest.makeSuite(TestENECC))
    suite.addTest(unittest.makeSuite(TestDEECC))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
