"""
Unit Test for ECDSA Digital Signature functions - Black Box Testing
Module: MahuCrypt_app.cryptography.signature
Functions: sign_ECDSA(string, public_key, private_key), verify_ECDSA(hash_message, signed_x, public_sign_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: ECDSA (Elliptic Curve Digital Signature Algorithm) generation and verification
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.signature import sign_ECDSA, verify_ECDSA
from MahuCrypt_app.cryptography.public_key_cryptography import create_ECDSA_keys


class TestSignECDSA(unittest.TestCase):
    """
    Black Box Testing for sign_ECDSA(string, public_key, private_key)
    
    ECDSA Digital Signature Generation:
    - Input: plaintext string, public_key dict with {p, q, a, G}, private_key int (d)
    - Process: 
      * Split into 4-char blocks, convert to int
      * For each block: choose random k in [1, q-1]
      * kG = k*G (point multiplication)
      * r = x-coordinate of kG mod q
      * s = k^(-1) * (hash + d*r) mod q
    - Output: Tuple (signed_x_ECDSA, sub_str_base10) - BOTH ARE STRINGS
      * signed_x_ECDSA: String representation of list of (r, s) tuples
      * sub_str_base10: String representation of list of hashed message values
    - Note: NON-DETERMINISTIC due to random k
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test ECDSA keys"""
        # Standard curve parameters (small for testing)
        cls.p = 23  # Prime for curve
        cls.a = 1   # Curve parameter
        cls.b = 1   # Curve parameter
        cls.n = 28  # Order approximation (for q calculation)
        
        keys = create_ECDSA_keys(cls.p, cls.a, cls.b, cls.n)
        cls.public_key = keys["public_key"]
        cls.private_key = int(keys["private_key"])
        
        # Extract values
        cls.q = int(cls.public_key["q"])
        cls.G = eval(cls.public_key["G"])
        cls.Q = eval(cls.public_key["Q"])
    
    # TC01: PE1 - Short string (4 char)
    def test_tc01_short_string(self):
        """Test case TC01: 4-character string"""
        signed, hashed = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
        self.assertIsInstance(hashed, str)
    
    # TC02: PE1 - Single character
    def test_tc02_single_char(self):
        """Test case TC02: Single character"""
        signed, hashed = sign_ECDSA("A", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
        self.assertIsInstance(hashed, str)
    
    # TC03: PE2 - Medium string (5 char)
    def test_tc03_medium_string(self):
        """Test case TC03: 5 characters"""
        signed, hashed = sign_ECDSA("HELLO", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC04: PE2 - 8 characters
    def test_tc04_eight_chars(self):
        """Test case TC04: 8 characters (2 blocks)"""
        signed, hashed = sign_ECDSA("TESTTEST", self.public_key, self.private_key)
        
        # Parse to check
        signed_list = eval(signed)
        self.assertEqual(len(signed_list), 2, "Should have 2 blocks")
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string (20 chars)"""
        signed, hashed = sign_ECDSA("A" * 20, self.public_key, self.private_key)
        
        signed_list = eval(signed)
        self.assertEqual(len(signed_list), 5, "Should have 5 blocks")
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        signed, hashed = sign_ECDSA("", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
        self.assertIsInstance(hashed, str)
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase(self):
        """Test case TC07: Lowercase input"""
        signed, hashed = sign_ECDSA("hello", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC08: PE5 - Uppercase
    def test_tc08_uppercase(self):
        """Test case TC08: Uppercase input"""
        signed, hashed = sign_ECDSA("HELLO", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC09: PE5 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case"""
        signed, hashed = sign_ECDSA("HeLLo", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC10: PE6 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        signed, hashed = sign_ECDSA("HELLO WORLD", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC11: PE6 - Special characters
    def test_tc11_special_chars(self):
        """Test case TC11: Special characters"""
        signed, hashed = sign_ECDSA("HELLO!", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
    
    # TC12: PE7 - Valid keys
    def test_tc12_valid_keys(self):
        """Test case TC12: Standard operation"""
        signed, hashed = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str)
        self.assertIsInstance(hashed, str)
    
    # TC13: PE8 - Missing p
    def test_tc13_missing_p(self):
        """Test case TC13: Key without p"""
        bad_key = {
            "q": self.public_key["q"],
            "a": self.public_key["a"],
            "G": self.public_key["G"]
        }
        
        try:
            signed, hashed = sign_ECDSA("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC14: PE8 - Missing q
    def test_tc14_missing_q(self):
        """Test case TC14: Key without q"""
        bad_key = {
            "p": self.public_key["p"],
            "a": self.public_key["a"],
            "G": self.public_key["G"]
        }
        
        try:
            signed, hashed = sign_ECDSA("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC15: PE8 - Missing a
    def test_tc15_missing_a(self):
        """Test case TC15: Key without a"""
        bad_key = {
            "p": self.public_key["p"],
            "q": self.public_key["q"],
            "G": self.public_key["G"]
        }
        
        try:
            signed, hashed = sign_ECDSA("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC16: PE8 - Missing G
    def test_tc16_missing_g(self):
        """Test case TC16: Key without G"""
        bad_key = {
            "p": self.public_key["p"],
            "q": self.public_key["q"],
            "a": self.public_key["a"]
        }
        
        try:
            signed, hashed = sign_ECDSA("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC17: Return structure
    def test_tc17_return_structure(self):
        """Test case TC17: Validate return is tuple of strings"""
        result = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        signed, hashed = result
        self.assertIsInstance(signed, str)
        self.assertIsInstance(hashed, str)
    
    # TC18: String format
    def test_tc18_string_format(self):
        """Test case TC18: Both outputs are strings"""
        signed, hashed = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, str, "Signed should be string")
        self.assertIsInstance(hashed, str, "Hashed should be string")
    
    # TC19: Non-deterministic signing
    def test_tc19_non_deterministic(self):
        """Test case TC19: Same input produces DIFFERENT signatures (random k)"""
        signed1, hashed1 = sign_ECDSA("TEST", self.public_key, self.private_key)
        signed2, hashed2 = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        # Hashes should be same
        self.assertEqual(hashed1, hashed2, "Hashes should be identical")
        # Signatures should differ (random k)
        self.assertNotEqual(signed1, signed2, "Signatures should differ due to random k")
    
    # TC20: Parseable signatures
    def test_tc20_parseable(self):
        """Test case TC20: Can parse signed string with eval()"""
        signed, hashed = sign_ECDSA("TEST", self.public_key, self.private_key)
        
        # Should be able to parse
        try:
            signed_list = eval(signed)
            hashed_list = eval(hashed)
            self.assertIsInstance(signed_list, list)
            self.assertIsInstance(hashed_list, list)
        except (SyntaxError, ValueError) as e:
            self.fail(f"Should be parseable: {e}")


class TestVerifyECDSA(unittest.TestCase):
    """
    Black Box Testing for verify_ECDSA(hash_message, signed_x, public_sign_key)
    
    ECDSA Signature Verification:
    - Input: hash_message list (parsed), signed_x list of tuples (parsed), public_sign_key dict {p, q, a, b, G, Q}
    - Process: For each signature (r, s):
      * w = s^(-1) mod q
      * u1 = hash * w mod q
      * u2 = r * w mod q
      * X = u1*G + u2*Q
      * Verify: x-coordinate of X mod q == r
    - Output: Boolean (True if valid, False if invalid)
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test ECDSA keys"""
        # Standard curve parameters
        cls.p = 23
        cls.a = 1
        cls.b = 1
        cls.n = 28
        
        keys = create_ECDSA_keys(cls.p, cls.a, cls.b, cls.n)
        cls.public_key_for_sign = keys["public_key"]
        cls.private_key = int(keys["private_key"])
        
        # Full public key for verify (needs b and Q)
        cls.public_sign_key = {
            "p": cls.public_key_for_sign["p"],
            "q": cls.public_key_for_sign["q"],
            "a": cls.public_key_for_sign["a"],
            "b": str(cls.b),
            "G": cls.public_key_for_sign["G"],
            "Q": cls.public_key_for_sign["Q"]
        }
        
        cls.q = int(cls.public_key_for_sign["q"])
    
    # TC01: PE1 - Valid signature
    def test_tc01_valid_signature(self):
        """Test case TC01: Verify valid signature"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result, "Valid signature should return True")
    
    # TC02: PE2 - Invalid signature (tampered)
    def test_tc02_invalid_signature(self):
        """Test case TC02: Tampered signature"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        # Modify signature (r)
        r, s = signed[0]
        signed[0] = ((r + 1) % self.q, s)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertFalse(result, "Tampered signature should return False")
    
    # TC03: PE3 - Invalid hash (modified message)
    def test_tc03_invalid_hash(self):
        """Test case TC03: Modified message hash"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        # Modify hash
        hashed[0] = (hashed[0] + 1) % self.q
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertFalse(result, "Modified hash should return False")
    
    # TC04: PE4 - Wrong public key
    def test_tc04_wrong_public_key(self):
        """Test case TC04: Wrong public key"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        wrong_key = self.public_sign_key.copy()
        wrong_key["q"] = str(int(self.public_sign_key["q"]) + 1)
        
        try:
            result = verify_ECDSA(hashed, signed, wrong_key)
            # Might fail or return False
        except Exception:
            pass
    
    # TC05: PE5 - Empty lists
    def test_tc05_empty_lists(self):
        """Test case TC05: Empty signature/hash"""
        result = verify_ECDSA([], [], self.public_sign_key)
        
        # Empty should pass (no blocks to verify)
        self.assertTrue(result, "Empty lists should return True")
    
    # TC06: PE6 - Single block
    def test_tc06_single_block(self):
        """Test case TC06: Single block verification"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result)
    
    # TC07: PE6 - Multiple blocks
    def test_tc07_multiple_blocks(self):
        """Test case TC07: Multi-block verification"""
        signed_str, hashed_str = sign_ECDSA("HELLO", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result)
    
    # TC08: PE7 - Mismatched lengths
    def test_tc08_mismatched_lengths(self):
        """Test case TC08: Different list lengths"""
        signed_str, hashed_str = sign_ECDSA("HELLO", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        # Remove one element
        signed_short = signed[:-1]
        
        try:
            result = verify_ECDSA(hashed, signed_short, self.public_sign_key)
            # Might error or return False
        except (IndexError, Exception):
            pass
    
    # TC09: PE8 - Modified one block
    def test_tc09_partial_tampering(self):
        """Test case TC09: One block tampered"""
        signed_str, hashed_str = sign_ECDSA("TESTTEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        # Modify second signature
        if len(signed) > 1:
            r, s = signed[1]
            signed[1] = ((r + 1) % self.q, s)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertFalse(result, "Partial tampering should fail")
    
    # TC10: PE9 - Round trip TEST
    def test_tc10_roundtrip_test(self):
        """Test case TC10: End-to-end TEST"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result, "Round trip should succeed")
    
    # TC11: PE9 - Round trip HELLO
    def test_tc11_roundtrip_hello(self):
        """Test case TC11: End-to-end HELLO"""
        signed_str, hashed_str = sign_ECDSA("HELLO", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result)
    
    # TC12: PE9 - Round trip long text
    def test_tc12_roundtrip_long(self):
        """Test case TC12: Long text round trip"""
        signed_str, hashed_str = sign_ECDSA("A" * 20, self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertTrue(result)
    
    # TC13: Return type
    def test_tc13_return_type(self):
        """Test case TC13: Returns boolean"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertIsInstance(result, bool)
    
    # TC14: True case exact
    def test_tc14_true_exact(self):
        """Test case TC14: Returns exactly True"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertIs(result, True, "Should be exactly True, not truthy")
    
    # TC15: False case exact
    def test_tc15_false_exact(self):
        """Test case TC15: Returns exactly False"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        # Tamper
        r, s = signed[0]
        signed[0] = ((r + 1) % self.q, s)
        
        result = verify_ECDSA(hashed, signed, self.public_sign_key)
        self.assertIs(result, False, "Should be exactly False, not falsy")
    
    # TC16: Missing p
    def test_tc16_missing_p(self):
        """Test case TC16: Key without p"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        bad_key = {k: v for k, v in self.public_sign_key.items() if k != "p"}
        
        try:
            result = verify_ECDSA(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC17: Missing q
    def test_tc17_missing_q(self):
        """Test case TC17: Key without q"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        bad_key = {k: v for k, v in self.public_sign_key.items() if k != "q"}
        
        try:
            result = verify_ECDSA(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC18: Missing a
    def test_tc18_missing_a(self):
        """Test case TC18: Key without a"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        bad_key = {k: v for k, v in self.public_sign_key.items() if k != "a"}
        
        try:
            result = verify_ECDSA(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC19: Missing G
    def test_tc19_missing_g(self):
        """Test case TC19: Key without G"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        bad_key = {k: v for k, v in self.public_sign_key.items() if k != "G"}
        
        try:
            result = verify_ECDSA(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC20: Missing Q
    def test_tc20_missing_q_point(self):
        """Test case TC20: Key without Q"""
        signed_str, hashed_str = sign_ECDSA("TEST", self.public_key_for_sign, self.private_key)
        signed = eval(signed_str)
        hashed = eval(hashed_str)
        
        bad_key = {k: v for k, v in self.public_sign_key.items() if k != "Q"}
        
        try:
            result = verify_ECDSA(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSignECDSA))
    suite.addTest(unittest.makeSuite(TestVerifyECDSA))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
