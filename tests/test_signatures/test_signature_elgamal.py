"""
Unit Test for ElGamal Digital Signature functions - Black Box Testing
Module: MahuCrypt_app.cryptography.signature
Functions: sign_ELGAMAL(string, public_key, private_key), verify_ELGAMAL(hash_message, sign_x_Elgamal, public_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: ElGamal digital signature generation and verification
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.signature import sign_ELGAMAL, verify_ELGAMAL
from MahuCrypt_app.cryptography.public_key_cryptography import create_ELGAMAL_keys


class TestSignELGAMAL(unittest.TestCase):
    """
    Black Box Testing for sign_ELGAMAL(string, public_key, private_key)
    
    ElGamal Digital Signature Generation:
    - Input: plaintext string, public_key dict with {p, alpha}, private_key int (a)
    - Process: 
      * Split into 4-char blocks, convert to int
      * For each block: choose random k where gcd(k, p-1) = 1
      * gamma = alpha^k mod p
      * delta = (m - a*gamma) * k^(-1) mod (p-1)
    - Output: Tuple (sign_x_Elgamal, sub_str_base10)
      * sign_x_Elgamal: List of (gamma, delta) tuples
      * sub_str_base10: List of hashed message values
    - Note: NON-DETERMINISTIC due to random k
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test ElGamal keys"""
        keys = create_ELGAMAL_keys(32)
        cls.public_key = keys["public_key"]
        cls.private_key = int(keys["private_key - a"])
        
        # Extract values for testing
        cls.p = int(cls.public_key["p"])
        cls.alpha = int(cls.public_key["alpha"])
        cls.beta = int(cls.public_key["beta"])
    
    # TC01: PE1 - Short string (4 char)
    def test_tc01_short_string(self):
        """Test case TC01: 4-character string"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
        self.assertGreater(len(signed), 0)
    
    # TC02: PE1 - Single character
    def test_tc02_single_char(self):
        """Test case TC02: Single character"""
        signed, hashed = sign_ELGAMAL("A", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC03: PE2 - Medium string (5 char)
    def test_tc03_medium_string(self):
        """Test case TC03: 5 characters"""
        signed, hashed = sign_ELGAMAL("HELLO", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 1, "Should have multiple blocks")
    
    # TC04: PE2 - 8 characters
    def test_tc04_eight_chars(self):
        """Test case TC04: 8 characters (2 blocks)"""
        signed, hashed = sign_ELGAMAL("TESTTEST", self.public_key, self.private_key)
        
        self.assertEqual(len(signed), 2, "Should have 2 blocks of 4 chars")
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string (20 chars)"""
        signed, hashed = sign_ELGAMAL("A" * 20, self.public_key, self.private_key)
        
        self.assertEqual(len(signed), 5, "Should have 5 blocks")
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        signed, hashed = sign_ELGAMAL("", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase(self):
        """Test case TC07: Lowercase input"""
        signed, hashed = sign_ELGAMAL("hello", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC08: PE5 - Uppercase
    def test_tc08_uppercase(self):
        """Test case TC08: Uppercase input"""
        signed, hashed = sign_ELGAMAL("HELLO", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC09: PE5 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case"""
        signed, hashed = sign_ELGAMAL("HeLLo", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC10: PE6 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        signed, hashed = sign_ELGAMAL("HELLO WORLD", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC11: PE6 - Special characters
    def test_tc11_special_chars(self):
        """Test case TC11: Special characters"""
        signed, hashed = sign_ELGAMAL("HELLO!", self.public_key, self.private_key)
        
        self.assertGreater(len(signed), 0)
    
    # TC12: PE7 - Valid keys
    def test_tc12_valid_keys(self):
        """Test case TC12: Standard operation"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC13: PE8 - Missing p
    def test_tc13_missing_p(self):
        """Test case TC13: Key without p"""
        bad_key = {"alpha": self.public_key["alpha"]}
        
        try:
            signed, hashed = sign_ELGAMAL("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC14: PE8 - Missing alpha
    def test_tc14_missing_alpha(self):
        """Test case TC14: Key without alpha"""
        bad_key = {"p": self.public_key["p"]}
        
        try:
            signed, hashed = sign_ELGAMAL("TEST", bad_key, self.private_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC15: PE9 - Invalid private key
    def test_tc15_invalid_private_key(self):
        """Test case TC15: Wrong private key"""
        wrong_a = (self.private_key + 1) % (self.p - 1)
        
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, wrong_a)
        # Will produce invalid signature
        self.assertIsInstance(signed, list)
    
    # TC16: Return structure
    def test_tc16_return_structure(self):
        """Test case TC16: Validate return is tuple of lists"""
        result = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        signed, hashed = result
        self.assertIsInstance(signed, list)
        self.assertIsInstance(hashed, list)
    
    # TC17: Signature format (tuples)
    def test_tc17_signature_format(self):
        """Test case TC17: Signatures are tuples (gamma, delta)"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        for sig in signed:
            self.assertIsInstance(sig, tuple, "Each signature should be tuple")
            self.assertEqual(len(sig), 2, "Signature tuple should be (gamma, delta)")
    
    # TC18: Hash values are integers
    def test_tc18_hash_integers(self):
        """Test case TC18: All hash values are integers"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        for h in hashed:
            self.assertIsInstance(h, int, "Hash should be int")
    
    # TC19: Non-deterministic signing
    def test_tc19_non_deterministic(self):
        """Test case TC19: Same input produces DIFFERENT signatures (random k)"""
        signed1, hashed1 = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        signed2, hashed2 = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        # Hashes should be same
        self.assertEqual(hashed1, hashed2, "Hashes should be identical")
        # Signatures should differ (random k)
        self.assertNotEqual(signed1, signed2, "Signatures should differ due to random k")
    
    # TC20: Gamma/delta are integers
    def test_tc20_gamma_delta_integers(self):
        """Test case TC20: Gamma and delta are integers"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key, self.private_key)
        
        for gamma, delta in signed:
            self.assertIsInstance(gamma, int, "Gamma should be int")
            self.assertIsInstance(delta, int, "Delta should be int")


class TestVerifyELGAMAL(unittest.TestCase):
    """
    Black Box Testing for verify_ELGAMAL(hash_message, sign_x_Elgamal, public_key)
    
    ElGamal Signature Verification:
    - Input: hash_message list, sign_x_Elgamal list of tuples, public_key dict {alpha, beta, p}
    - Process: For each block, verify: beta^gamma * gamma^delta ≡ alpha^x (mod p)
    - Output: Boolean (True if valid, False if invalid)
    
    Test Plan: 20 test cases
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test ElGamal keys"""
        keys = create_ELGAMAL_keys(32)
        cls.public_key_for_sign = keys["public_key"]
        cls.private_key = int(keys["private_key - a"])
        
        # Create public_key for verify (needs alpha, beta, p)
        cls.p = int(cls.public_key_for_sign["p"])
        cls.alpha = int(cls.public_key_for_sign["alpha"])
        cls.beta = int(cls.public_key_for_sign["beta"])
        
        # Full public key for verify_ELGAMAL
        cls.public_key = {
            "alpha": cls.public_key_for_sign["alpha"],
            "beta": cls.public_key_for_sign["beta"],
            "p": cls.public_key_for_sign["p"]
        }
    
    # TC01: PE1 - Valid signature
    def test_tc01_valid_signature(self):
        """Test case TC01: Verify valid signature"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertTrue(result, "Valid signature should return True")
    
    # TC02: PE2 - Invalid signature (tampered)
    def test_tc02_invalid_signature(self):
        """Test case TC02: Tampered signature"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        # Modify signature (gamma)
        gamma, delta = signed[0]
        signed[0] = ((gamma + 1) % self.p, delta)
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertFalse(result, "Tampered signature should return False")
    
    # TC03: PE3 - Invalid hash (modified message)
    def test_tc03_invalid_hash(self):
        """Test case TC03: Modified message hash"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        # Modify hash
        hashed[0] = (hashed[0] + 1) % self.p
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertFalse(result, "Modified hash should return False")
    
    # TC04: PE4 - Wrong public key
    def test_tc04_wrong_public_key(self):
        """Test case TC04: Wrong public key"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        wrong_key = self.public_key.copy()
        wrong_key["beta"] = str((int(self.public_key["beta"]) + 1) % self.p)
        
        result = verify_ELGAMAL(hashed, signed, wrong_key)
        self.assertFalse(result, "Wrong key should return False")
    
    # TC05: PE5 - Empty lists
    def test_tc05_empty_lists(self):
        """Test case TC05: Empty signature/hash"""
        result = verify_ELGAMAL([], [], self.public_key)
        
        # Empty should pass (no blocks to verify)
        self.assertTrue(result, "Empty lists should return True")
    
    # TC06: PE6 - Single block
    def test_tc06_single_block(self):
        """Test case TC06: Single block verification"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertTrue(result)
    
    # TC07: PE6 - Multiple blocks
    def test_tc07_multiple_blocks(self):
        """Test case TC07: Multi-block verification"""
        signed, hashed = sign_ELGAMAL("HELLO", self.public_key_for_sign, self.private_key)
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertTrue(result)
    
    # TC08: PE7 - Mismatched lengths
    def test_tc08_mismatched_lengths(self):
        """Test case TC08: Different list lengths"""
        signed, hashed = sign_ELGAMAL("HELLO", self.public_key_for_sign, self.private_key)
        # Remove one element
        signed_short = signed[:-1]
        
        try:
            result = verify_ELGAMAL(hashed, signed_short, self.public_key)
            # Might error or return False
        except (IndexError, Exception):
            pass
    
    # TC09: PE8 - Modified one block
    def test_tc09_partial_tampering(self):
        """Test case TC09: One block tampered"""
        signed, hashed = sign_ELGAMAL("TESTTEST", self.public_key_for_sign, self.private_key)
        # Modify second signature
        if len(signed) > 1:
            gamma, delta = signed[1]
            signed[1] = ((gamma + 1) % self.p, delta)
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertFalse(result, "Partial tampering should fail")
    
    # TC10: PE9 - Round trip TEST
    def test_tc10_roundtrip_test(self):
        """Test case TC10: End-to-end TEST"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertTrue(result, "Round trip should succeed")
    
    # TC11: PE9 - Round trip HELLO
    def test_tc11_roundtrip_hello(self):
        """Test case TC11: End-to-end HELLO"""
        signed, hashed = sign_ELGAMAL("HELLO", self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertTrue(result)
    
    # TC12: PE9 - Round trip long text
    def test_tc12_roundtrip_long(self):
        """Test case TC12: Long text round trip"""
        signed, hashed = sign_ELGAMAL("A" * 20, self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertTrue(result)
    
    # TC13: PE10 - Case sensitivity
    def test_tc13_case_sensitivity(self):
        """Test case TC13: Different cases produce different hashes"""
        signed1, hashed1 = sign_ELGAMAL("HELLO", self.public_key_for_sign, self.private_key)
        signed2, hashed2 = sign_ELGAMAL("hello", self.public_key_for_sign, self.private_key)
        
        # Verify with mismatched hash
        result = verify_ELGAMAL(hashed1, signed2, self.public_key)
        self.assertFalse(result, "Different cases should fail verification")
    
    # TC14: Return type
    def test_tc14_return_type(self):
        """Test case TC14: Returns boolean"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertIsInstance(result, bool)
    
    # TC15: True case exact
    def test_tc15_true_exact(self):
        """Test case TC15: Returns exactly True"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        
        self.assertIs(result, True, "Should be exactly True, not truthy")
    
    # TC16: False case exact
    def test_tc16_false_exact(self):
        """Test case TC16: Returns exactly False"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        # Tamper
        gamma, delta = signed[0]
        signed[0] = ((gamma + 1) % self.p, delta)
        
        result = verify_ELGAMAL(hashed, signed, self.public_key)
        self.assertIs(result, False, "Should be exactly False, not falsy")
    
    # TC17: Non-tuple in signed
    def test_tc17_non_tuple_signed(self):
        """Test case TC17: Non-tuple signature value"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        signed[0] = "not_a_tuple"
        
        try:
            result = verify_ELGAMAL(hashed, signed, self.public_key)
            # Should error
        except (TypeError, ValueError):
            pass
    
    # TC18: Missing alpha
    def test_tc18_missing_alpha(self):
        """Test case TC18: Key without alpha"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        bad_key = {"beta": self.public_key["beta"], "p": self.public_key["p"]}
        
        try:
            result = verify_ELGAMAL(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC19: Missing beta
    def test_tc19_missing_beta(self):
        """Test case TC19: Key without beta"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        bad_key = {"alpha": self.public_key["alpha"], "p": self.public_key["p"]}
        
        try:
            result = verify_ELGAMAL(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC20: Missing p
    def test_tc20_missing_p(self):
        """Test case TC20: Key without p"""
        signed, hashed = sign_ELGAMAL("TEST", self.public_key_for_sign, self.private_key)
        bad_key = {"alpha": self.public_key["alpha"], "beta": self.public_key["beta"]}
        
        try:
            result = verify_ELGAMAL(hashed, signed, bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSignELGAMAL))
    suite.addTest(unittest.makeSuite(TestVerifyELGAMAL))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
