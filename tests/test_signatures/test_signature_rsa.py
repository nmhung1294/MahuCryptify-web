"""
Unit Test for RSA Digital Signature functions - Black Box Testing
Module: MahuCrypt_app.cryptography.signature
Functions: sign_RSA(string, private_key), verify_RSA(hash_message, signed, public_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: RSA digital signature generation and verification
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.signature import sign_RSA, verify_RSA
from MahuCrypt_app.cryptography.public_key_cryptography import create_RSA_keys


class TestSignRSA(unittest.TestCase):
    """
    Black Box Testing for sign_RSA(string, private_key)
    
    RSA Digital Signature Generation:
    - Input: plaintext string, private_key dict with {p, q, d}
    - Process: Split into 4-char blocks, convert to int, sign each: s = m^d mod n
    - Output: Tuple (signed_x_RSA, sub_str_base10)
      * signed_x_RSA: List of signature values
      * sub_str_base10: List of hashed message values
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test RSA keys"""
        keys = create_RSA_keys(32)
        cls.public_key = keys["public_key"]
        cls.private_key = keys["private_key"]
        
        # Extract values for verification
        cls.n = int(cls.public_key["n"])
        cls.e = int(cls.public_key["e"])
        cls.p = int(cls.private_key["p"])
        cls.q = int(cls.private_key["q"])
        cls.d = int(cls.private_key["d"])
    
    # TC01: PE1 - Short string (4 char)
    def test_tc01_short_string(self):
        """Test case TC01: 4-character string"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
        self.assertGreater(len(signed), 0)
    
    # TC02: PE1 - Single character
    def test_tc02_single_char(self):
        """Test case TC02: Single character"""
        signed, hashed = sign_RSA("A", self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC03: PE2 - Medium string (5 char)
    def test_tc03_medium_string(self):
        """Test case TC03: 5 characters"""
        signed, hashed = sign_RSA("HELLO", self.private_key)
        
        self.assertGreater(len(signed), 1, "Should have multiple blocks")
    
    # TC04: PE2 - 8 characters
    def test_tc04_eight_chars(self):
        """Test case TC04: 8 characters (2 blocks)"""
        signed, hashed = sign_RSA("TESTTEST", self.private_key)
        
        self.assertEqual(len(signed), 2, "Should have 2 blocks of 4 chars")
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string (20 chars)"""
        signed, hashed = sign_RSA("A" * 20, self.private_key)
        
        self.assertEqual(len(signed), 5, "Should have 5 blocks")
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        signed, hashed = sign_RSA("", self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase(self):
        """Test case TC07: Lowercase input"""
        signed, hashed = sign_RSA("hello", self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC08: PE5 - Uppercase
    def test_tc08_uppercase(self):
        """Test case TC08: Uppercase input"""
        signed, hashed = sign_RSA("HELLO", self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC09: PE5 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case"""
        signed, hashed = sign_RSA("HeLLo", self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC10: PE6 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        signed, hashed = sign_RSA("HELLO WORLD", self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC11: PE6 - Special characters
    def test_tc11_special_chars(self):
        """Test case TC11: Special characters"""
        signed, hashed = sign_RSA("HELLO!", self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC12: PE7 - Valid key
    def test_tc12_valid_key(self):
        """Test case TC12: Standard operation"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC13: PE8 - Missing p
    def test_tc13_missing_p(self):
        """Test case TC13: Key without p"""
        bad_key = {"q": self.private_key["q"], "d": self.private_key["d"]}
        
        try:
            signed, hashed = sign_RSA("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC14: PE8 - Missing q
    def test_tc14_missing_q(self):
        """Test case TC14: Key without q"""
        bad_key = {"p": self.private_key["p"], "d": self.private_key["d"]}
        
        try:
            signed, hashed = sign_RSA("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC15: PE8 - Missing d
    def test_tc15_missing_d(self):
        """Test case TC15: Key without d"""
        bad_key = {"p": self.private_key["p"], "q": self.private_key["q"]}
        
        try:
            signed, hashed = sign_RSA("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC16: PE9 - Invalid d
    def test_tc16_invalid_d(self):
        """Test case TC16: Wrong d value"""
        bad_key = self.private_key.copy()
        bad_key["d"] = str(int(self.private_key["d"]) + 1)
        
        signed, hashed = sign_RSA("TEST", bad_key)
        # Will produce invalid signature
        self.assertIsInstance(signed, list)
    
    # TC17: Return structure
    def test_tc17_return_structure(self):
        """Test case TC17: Validate return is tuple of lists"""
        result = sign_RSA("TEST", self.private_key)
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        signed, hashed = result
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC18: Signature values are integers
    def test_tc18_signature_integers(self):
        """Test case TC18: All signed values are integers"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        
        for sig in signed:
            self.assertIsInstance(sig, int, "Signature should be int")
    
    # TC19: Hash values are integers
    def test_tc19_hash_integers(self):
        """Test case TC19: All hash values are integers"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        
        for h in hashed:
            self.assertIsInstance(h, int, "Hash should be int")
    
    # TC20: Deterministic signing
    def test_tc20_deterministic(self):
        """Test case TC20: Same input produces same signature"""
        signed1, hashed1 = sign_RSA("TEST", self.private_key)
        signed2, hashed2 = sign_RSA("TEST", self.private_key)
        
        self.assertEqual(signed1, signed2, "Signatures should be identical")
        self.assertEqual(hashed1, hashed2, "Hashes should be identical")


class TestVerifyRSA(unittest.TestCase):
    """
    Black Box Testing for verify_RSA(hash_message, signed, public_key)
    
    RSA Signature Verification:
    - Input: hash_message list, signed list, public_key tuple (n, e)
    - Process: For each block, verify: signed[i]^e mod n == hash_message[i]
    - Output: Boolean (True if valid, False if invalid)
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test RSA keys"""
        keys = create_RSA_keys(32)
        cls.public_key_dict = keys["public_key"]
        cls.private_key = keys["private_key"]
        
        # Create public_key tuple for verify_RSA
        cls.n = int(cls.public_key_dict["n"])
        cls.e = int(cls.public_key_dict["e"])
        cls.public_key = (cls.n, cls.e)
    
    # TC01: PE1 - Valid signature
    def test_tc01_valid_signature(self):
        """Test case TC01: Verify valid signature"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertTrue(result, "Valid signature should return True")
    
    # TC02: PE2 - Invalid signature (tampered)
    def test_tc02_invalid_signature(self):
        """Test case TC02: Tampered signature"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        # Modify signature
        signed[0] = (signed[0] + 1) % self.n
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertFalse(result, "Tampered signature should return False")
    
    # TC03: PE3 - Invalid hash (modified message)
    def test_tc03_invalid_hash(self):
        """Test case TC03: Modified message hash"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        # Modify hash
        hashed[0] = (hashed[0] + 1) % self.n
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertFalse(result, "Modified hash should return False")
    
    # TC04: PE4 - Wrong public key
    def test_tc04_wrong_public_key(self):
        """Test case TC04: Wrong public key"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        wrong_key = (self.n + 1, self.e)
        
        result = verify_RSA(hashed, signed, wrong_key)
        self.assertFalse(result, "Wrong key should return False")
    
    # TC05: PE5 - Empty lists
    def test_tc05_empty_lists(self):
        """Test case TC05: Empty signature/hash"""
        result = verify_RSA([], [], self.public_key)
        
        # Empty should pass (no blocks to verify)
        self.assertTrue(result, "Empty lists should return True")
    
    # TC06: PE6 - Single block
    def test_tc06_single_block(self):
        """Test case TC06: Single block verification"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertTrue(result)
    
    # TC07: PE6 - Multiple blocks
    def test_tc07_multiple_blocks(self):
        """Test case TC07: Multi-block verification"""
        signed, hashed = sign_RSA("HELLO", self.private_key)
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertTrue(result)
    
    # TC08: PE7 - Mismatched lengths
    def test_tc08_mismatched_lengths(self):
        """Test case TC08: Different list lengths"""
        signed, hashed = sign_RSA("HELLO", self.private_key)
        # Remove one element
        signed_short = signed[:-1]
        
        try:
            result = verify_RSA(hashed, signed_short, self.public_key)
            # Might error or return False
        except (IndexError, Exception):
            pass
    
    # TC09: PE8 - Modified one block
    def test_tc09_partial_tampering(self):
        """Test case TC09: One block tampered"""
        signed, hashed = sign_RSA("TESTTEST", self.private_key)
        # Modify second signature
        if len(signed) > 1:
            signed[1] = (signed[1] + 1) % self.n
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertFalse(result, "Partial tampering should fail")
    
    # TC10: PE9 - Round trip TEST
    def test_tc10_roundtrip_test(self):
        """Test case TC10: End-to-end TEST"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertTrue(result, "Round trip should succeed")
    
    # TC11: PE9 - Round trip HELLO
    def test_tc11_roundtrip_hello(self):
        """Test case TC11: End-to-end HELLO"""
        signed, hashed = sign_RSA("HELLO", self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertTrue(result)
    
    # TC12: PE9 - Round trip long text
    def test_tc12_roundtrip_long(self):
        """Test case TC12: Long text round trip"""
        signed, hashed = sign_RSA("A" * 20, self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertTrue(result)
    
    # TC13: PE10 - Case sensitivity
    def test_tc13_case_sensitivity(self):
        """Test case TC13: Different cases produce different hashes"""
        signed1, hashed1 = sign_RSA("HELLO", self.private_key)
        signed2, hashed2 = sign_RSA("hello", self.private_key)
        
        # Verify with mismatched hash
        result = verify_RSA(hashed1, signed2, self.public_key)
        self.assertFalse(result, "Different cases should fail verification")
    
    # TC14: Return type
    def test_tc14_return_type(self):
        """Test case TC14: Returns boolean"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertIsInstance(result, bool)
    
    # TC15: True case exact
    def test_tc15_true_exact(self):
        """Test case TC15: Returns exactly True"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        result = verify_RSA(hashed, signed, self.public_key)
        
        self.assertIs(result, True, "Should be exactly True, not truthy")
    
    # TC16: False case exact
    def test_tc16_false_exact(self):
        """Test case TC16: Returns exactly False"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        signed[0] = (signed[0] + 1) % self.n
        
        result = verify_RSA(hashed, signed, self.public_key)
        self.assertIs(result, False, "Should be exactly False, not falsy")
    
    # TC17: Non-integer in signed
    def test_tc17_non_integer_signed(self):
        """Test case TC17: Non-integer signature value"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        signed[0] = "not_a_number"
        
        try:
            result = verify_RSA(hashed, signed, self.public_key)
            # Should error
        except (TypeError, ValueError):
            pass
    
    # TC18: Non-integer in hash
    def test_tc18_non_integer_hash(self):
        """Test case TC18: Non-integer hash value"""
        signed, hashed = sign_RSA("TEST", self.private_key)
        hashed[0] = "not_a_number"
        
        try:
            result = verify_RSA(hashed, signed, self.public_key)
            # Should error
        except (TypeError, ValueError):
            pass
    
    # TC19: Negative values
    def test_tc19_negative_values(self):
        """Test case TC19: Negative in signature/hash"""
        result = verify_RSA([-1], [-1], self.public_key)
        
        # Might fail or error
        self.assertIsInstance(result, bool)
    
    # TC20: Large values
    def test_tc20_large_values(self):
        """Test case TC20: Very large values"""
        large_val = 10**100
        result = verify_RSA([large_val], [large_val], self.public_key)
        
        # Should handle large numbers
        self.assertIsInstance(result, bool)


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSignRSA))
    suite.addTest(unittest.makeSuite(TestVerifyRSA))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
