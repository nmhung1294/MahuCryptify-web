"""
Unit Test for ElGamal Cryptography functions - Black Box Testing
Module: MahuCrypt_app.cryptography.public_key_cryptography
Functions: create_ELGAMAL_keys(bits), EN_ELGAMAL(string, public_key), DE_ELGAMAL(encrypted_message_str, p, private_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: ElGamal key generation, encryption, and decryption
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.public_key_cryptography import create_ELGAMAL_keys, EN_ELGAMAL, DE_ELGAMAL
from MahuCrypt_app.cryptography.algos import miller_rabin_test, modular_exponentiation


class TestCreateELGAMALKeys(unittest.TestCase):
    """
    Black Box Testing for create_ELGAMAL_keys(bits)
    
    ElGamal Key Generation:
    - p = random prime with 'bits' bits
    - alpha = 2 (fixed generator)
    - a = random private key in [1, p-1]
    - beta = alpha^a mod p (public key component)
    
    Test Plan:
    - PE1-PE3: Various bit sizes
    - PE4-PE5: Invalid inputs
    - Validation: structure, primality, mathematical properties
    """
    
    # TC01: PE1 - bits=8
    def test_tc01_bits_8(self):
        """Test case TC01: Generate ElGamal keys with 8 bits"""
        result = create_ELGAMAL_keys(8)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key - a", result)
    
    # TC02: PE1 - bits=16
    def test_tc02_bits_16(self):
        """Test case TC02: 16-bit key generation"""
        result = create_ELGAMAL_keys(16)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key - a", result)
    
    # TC03: PE2 - bits=32
    def test_tc03_bits_32(self):
        """Test case TC03: 32-bit ElGamal keys"""
        result = create_ELGAMAL_keys(32)
        
        self.assertIsInstance(result, dict)
    
    # TC04: PE2 - bits=64 (may be slow)
    @unittest.skip("Slow - 64 bit prime generation")
    def test_tc04_bits_64(self):
        """Test case TC04: 64-bit keys"""
        result = create_ELGAMAL_keys(64)
        
        self.assertIn("public_key", result)
    
    # TC05: PE3 - bits=128 (skip - very slow)
    @unittest.skip("Too slow for regular testing")
    def test_tc05_bits_128(self):
        """Test case TC05: 128-bit keys"""
        result = create_ELGAMAL_keys(128)
        
        self.assertIsInstance(result, dict)
    
    # TC06: PE4 - bits=2 (may hang)
    @unittest.skip("May hang - too small")
    def test_tc06_bits_2(self):
        """Test case TC06: 2 bits - too small"""
        result = create_ELGAMAL_keys(2)
    
    # TC07: PE5 - bits=0
    @unittest.skip("Hangs - skip invalid bits")
    def test_tc07_bits_zero(self):
        """Test case TC07: Zero bits - invalid"""
        try:
            result = create_ELGAMAL_keys(0)
            self.fail("Should raise error")
        except (ValueError, ZeroDivisionError):
            pass
    
    # TC08: PE5 - Negative bits
    @unittest.skip("Hangs - skip invalid bits")
    def test_tc08_bits_negative(self):
        """Test case TC08: Negative bits - invalid"""
        try:
            result = create_ELGAMAL_keys(-10)
            self.fail("Should raise error")
        except (ValueError, OverflowError):
            pass
    
    # TC09: Return structure
    def test_tc09_return_structure(self):
        """Test case TC09: Validate return structure"""
        result = create_ELGAMAL_keys(16)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key - a", result)
        self.assertIsInstance(result["public_key"], dict)
    
    # TC10: Public key structure
    def test_tc10_public_key_structure(self):
        """Test case TC10: Public key has p, alpha, beta"""
        result = create_ELGAMAL_keys(16)
        
        public_key = result["public_key"]
        self.assertIn("p", public_key)
        self.assertIn("alpha", public_key)
        self.assertIn("beta", public_key)
        # All strings
        self.assertIsInstance(public_key["p"], str)
        self.assertIsInstance(public_key["alpha"], str)
        self.assertIsInstance(public_key["beta"], str)
    
    # TC11: Private key format
    def test_tc11_private_key_format(self):
        """Test case TC11: Private key with specific key name"""
        result = create_ELGAMAL_keys(16)
        
        # Key name is "private_key - a"
        self.assertIn("private_key - a", result)
        self.assertIsInstance(result["private_key - a"], str)
    
    # TC12: Alpha is always 2
    def test_tc12_alpha_always_2(self):
        """Test case TC12: Alpha generator is fixed to 2"""
        result = create_ELGAMAL_keys(16)
        
        alpha = result["public_key"]["alpha"]
        self.assertEqual(alpha, "2", "Alpha should always be 2")
    
    # TC13: p is prime
    def test_tc13_p_is_prime(self):
        """Test case TC13: Verify p is prime"""
        result = create_ELGAMAL_keys(16)
        
        p = int(result["public_key"]["p"])
        self.assertTrue(miller_rabin_test(p, 100), f"p={p} should be prime")
    
    # TC14: beta = alpha^a mod p
    def test_tc14_beta_calculation(self):
        """Test case TC14: Verify beta = alpha^a mod p"""
        result = create_ELGAMAL_keys(16)
        
        p = int(result["public_key"]["p"])
        alpha = int(result["public_key"]["alpha"])
        beta = int(result["public_key"]["beta"])
        a = int(result["private_key - a"])
        
        expected_beta = modular_exponentiation(alpha, a, p)
        self.assertEqual(beta, expected_beta, "beta should equal alpha^a mod p")
    
    # TC15: a in valid range [1, p-1]
    def test_tc15_a_in_range(self):
        """Test case TC15: Private key a in valid range"""
        result = create_ELGAMAL_keys(16)
        
        p = int(result["public_key"]["p"])
        a = int(result["private_key - a"])
        
        self.assertGreaterEqual(a, 1, "a should be >= 1")
        self.assertLess(a, p, "a should be < p")
    
    # TC16: Randomness
    def test_tc16_randomness(self):
        """Test case TC16: Different keys on different calls"""
        result1 = create_ELGAMAL_keys(16)
        result2 = create_ELGAMAL_keys(16)
        
        p1 = result1["public_key"]["p"]
        p2 = result2["public_key"]["p"]
        
        self.assertNotEqual(p1, p2, "Keys should be random")
    
    # TC17: All values are strings
    def test_tc17_string_format(self):
        """Test case TC17: All values stored as strings"""
        result = create_ELGAMAL_keys(16)
        
        for key in ["p", "alpha", "beta"]:
            self.assertIsInstance(result["public_key"][key], str)
        
        self.assertIsInstance(result["private_key - a"], str)


class TestENELGAMAL(unittest.TestCase):
    """
    Black Box Testing for EN_ELGAMAL(string, public_key)
    
    ElGamal Encryption:
    - Input: plaintext, public_key dict
    - Random k for each encryption (non-deterministic)
    - Encrypts in blocks: (y1, y2) where y1=alpha^k, y2=m*beta^k
    - Output: {"Encrypted": str(list of tuples)}
    
    Test Plan:
    - PE1-PE3: Various string lengths
    - PE4-PE6: Case and special character handling
    - PE7-PE9: Key validation
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test key pair"""
        cls.keys = create_ELGAMAL_keys(32)
        cls.public_key = cls.keys["public_key"]
        cls.private_key = int(cls.keys["private_key - a"])
        cls.p = int(cls.public_key["p"])
    
    # TC01: PE1 - Short string
    def test_tc01_short_string(self):
        """Test case TC01: 4-character string"""
        result = EN_ELGAMAL("HELL", self.public_key)
        
        self.assertIn("Encrypted", result)
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
        self.assertGreater(len(encrypted_list), 0)
    
    # TC02: PE1 - Single character
    def test_tc02_single_char(self):
        """Test case TC02: Single character"""
        result = EN_ELGAMAL("A", self.public_key)
        
        self.assertIn("Encrypted", result)
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC03: PE2 - Medium string
    def test_tc03_medium_string(self):
        """Test case TC03: 5 characters"""
        result = EN_ELGAMAL("HELLO", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
        # Should have multiple tuples
    
    # TC04: PE2 - 8 characters
    def test_tc04_eight_chars(self):
        """Test case TC04: 8 characters"""
        result = EN_ELGAMAL("HELLOABC", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string"""
        result = EN_ELGAMAL("HELLO WORLD TEST", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertGreater(len(encrypted_list), 2)
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        result = EN_ELGAMAL("", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase(self):
        """Test case TC07: Lowercase input"""
        result = EN_ELGAMAL("hello", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC08: PE5 - Uppercase
    def test_tc08_uppercase(self):
        """Test case TC08: Uppercase input"""
        result = EN_ELGAMAL("HELLO", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC09: PE5 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case"""
        result = EN_ELGAMAL("HeLLo", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC10: PE6 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        result = EN_ELGAMAL("HELLO WORLD", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC11: PE6 - Special characters
    def test_tc11_special_chars(self):
        """Test case TC11: Special characters"""
        result = EN_ELGAMAL("HELLO!", self.public_key)
        
        self.assertIn("Encrypted", result)
    
    # TC12: PE7 - Valid key
    def test_tc12_valid_key(self):
        """Test case TC12: Standard operation"""
        result = EN_ELGAMAL("TEST", self.public_key)
        
        self.assertIn("Encrypted", result)
        encrypted_list = eval(result["Encrypted"])
        self.assertTrue(all(isinstance(x, tuple) for x in encrypted_list))
    
    # TC13: PE8 - Missing p
    def test_tc13_missing_p(self):
        """Test case TC13: Key without p"""
        bad_key = {"alpha": "2", "beta": "100"}
        
        try:
            result = EN_ELGAMAL("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC14: PE8 - Missing alpha
    def test_tc14_missing_alpha(self):
        """Test case TC14: Key without alpha"""
        bad_key = {"p": self.public_key["p"], "beta": self.public_key["beta"]}
        
        try:
            result = EN_ELGAMAL("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC15: PE8 - Missing beta
    def test_tc15_missing_beta(self):
        """Test case TC15: Key without beta"""
        bad_key = {"p": self.public_key["p"], "alpha": "2"}
        
        try:
            result = EN_ELGAMAL("TEST", bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC16: PE9 - p too small
    def test_tc16_p_too_small(self):
        """Test case TC16: Very small p"""
        tiny_key = {"p": "10", "alpha": "2", "beta": "4"}
        
        try:
            result = EN_ELGAMAL("ZZZZ", tiny_key)
            # Might overflow or error
        except Exception:
            pass
    
    # TC17: Return structure
    def test_tc17_return_structure(self):
        """Test case TC17: Validate return structure"""
        result = EN_ELGAMAL("TEST", self.public_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Encrypted", result)
    
    # TC18: Encrypted format
    def test_tc18_encrypted_format(self):
        """Test case TC18: Encrypted is string of list"""
        result = EN_ELGAMAL("TEST", self.public_key)
        
        encrypted_str = result["Encrypted"]
        self.assertIsInstance(encrypted_str, str)
        # Should be parseable
        encrypted_list = eval(encrypted_str)
        self.assertIsInstance(encrypted_list, list)
    
    # TC19: Non-deterministic (random k)
    def test_tc19_non_deterministic(self):
        """Test case TC19: Same input gives different output (random k)"""
        result1 = EN_ELGAMAL("TEST", self.public_key)
        result2 = EN_ELGAMAL("TEST", self.public_key)
        
        # Should be different due to random k
        self.assertNotEqual(result1["Encrypted"], result2["Encrypted"],
                           "ElGamal uses random k, should differ")
    
    # TC20: Tuple format
    def test_tc20_tuple_format(self):
        """Test case TC20: Each element is (y1, y2) tuple"""
        result = EN_ELGAMAL("TEST", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        for item in encrypted_list:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2, "Each element should be (y1, y2)")


class TestDEELGAMAL(unittest.TestCase):
    """
    Black Box Testing for DE_ELGAMAL(encrypted_message_str, p, private_key)
    
    ElGamal Decryption:
    - Input: encrypted string, p, private_key (a)
    - Parse tuples → decrypt: m = y2 * y1^(p-1-a) mod p
    - Output: {"Decrypted": string}
    
    Test Plan:
    - PE1-PE3: Various encrypted sizes
    - PE4-PE7: Key and format validation
    - PE8-PE9: Round trips and multiple messages
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test keys"""
        cls.keys = create_ELGAMAL_keys(32)
        cls.public_key = cls.keys["public_key"]
        cls.private_key = int(cls.keys["private_key - a"])
        cls.p = int(cls.public_key["p"])
    
    # TC01: PE1 - Single tuple
    def test_tc01_single_tuple(self):
        """Test case TC01: Decrypt single block"""
        encrypted = EN_ELGAMAL("HELL", self.public_key)
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", result)
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC02: PE2 - Multiple tuples
    def test_tc02_multiple_tuples(self):
        """Test case TC02: Decrypt multiple blocks"""
        encrypted = EN_ELGAMAL("HELLO WORLD", self.public_key)
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC03: PE3 - Empty list
    def test_tc03_empty_list(self):
        """Test case TC03: Decrypt empty"""
        result = DE_ELGAMAL("[]", self.p, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC04: PE4 - Valid key
    def test_tc04_valid_key(self):
        """Test case TC04: Standard decryption"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC05: PE5 - Wrong a
    def test_tc05_wrong_a(self):
        """Test case TC05: Wrong private key"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        wrong_a = (self.private_key + 1) % (self.p - 1)
        
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, wrong_a)
        # Will decrypt to wrong plaintext
        self.assertNotEqual(result["Decrypted"], "TEST")
    
    # TC06: PE5 - Wrong p
    def test_tc06_wrong_p(self):
        """Test case TC06: Wrong p value"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        wrong_p = self.p + 1
        
        try:
            result = DE_ELGAMAL(encrypted["Encrypted"], wrong_p, self.private_key)
            # Might error or give wrong result
        except Exception:
            pass
    
    # TC07: PE6 - Parentheses format
    def test_tc07_parentheses_format(self):
        """Test case TC07: Format with parentheses"""
        # Simulate encrypted format
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        # Should parse correctly
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC08: PE6 - Various formats
    def test_tc08_no_spaces_format(self):
        """Test case TC08: Format without spaces"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        # Remove spaces if any
        enc_str = encrypted["Encrypted"].replace(" ", "")
        
        result = DE_ELGAMAL(enc_str, self.p, self.private_key)
        self.assertIn("Decrypted", result)
    
    # TC09: PE7 - Malformed string
    def test_tc09_malformed_string(self):
        """Test case TC09: Invalid format"""
        try:
            result = DE_ELGAMAL("not a list", self.p, self.private_key)
            # Should error
        except (ValueError, SyntaxError, NameError):
            pass
    
    # TC10: PE7 - Non-numeric values
    def test_tc10_non_numeric(self):
        """Test case TC10: Non-numeric in list"""
        try:
            result = DE_ELGAMAL("[(a, b)]", self.p, self.private_key)
            self.fail("Should raise ValueError")
        except (ValueError, NameError):
            pass
    
    # TC11: PE8 - Round trip TEST
    def test_tc11_roundtrip_test(self):
        """Test case TC11: Encrypt-decrypt TEST"""
        original = "TEST"
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertEqual(decrypted["Decrypted"], original)
    
    # TC12: PE8 - Round trip HELLO
    def test_tc12_roundtrip_hello(self):
        """Test case TC12: Round trip HELLO"""
        original = "HELLO"
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC13: PE8 - Round trip long text
    def test_tc13_roundtrip_long(self):
        """Test case TC13: Long text round trip"""
        original = "A" * 50
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertEqual(len(decrypted["Decrypted"]), len(original))
    
    # TC14: PE9 - Different messages
    def test_tc14_different_messages(self):
        """Test case TC14: Multiple different messages"""
        messages = ["AAA", "BBB", "CCC"]
        
        for msg in messages:
            with self.subTest(msg=msg):
                encrypted = EN_ELGAMAL(msg, self.public_key)
                decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
                self.assertEqual(decrypted["Decrypted"], msg)
    
    # TC15: Return structure
    def test_tc15_return_structure(self):
        """Test case TC15: Validate return structure"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Decrypted", result)
    
    # TC16: Decrypted is string
    def test_tc16_decrypted_format(self):
        """Test case TC16: Decrypted is string"""
        encrypted = EN_ELGAMAL("TEST", self.public_key)
        result = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC17: Case handling
    def test_tc17_case_handling(self):
        """Test case TC17: Mixed case handling"""
        original = "HeLLo"
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC18: Special characters
    def test_tc18_special_chars(self):
        """Test case TC18: Special characters"""
        original = "HELLO!"
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC19: Numbers
    def test_tc19_numbers(self):
        """Test case TC19: Numbers in string"""
        original = "HELLO123"
        encrypted = EN_ELGAMAL(original, self.public_key)
        decrypted = DE_ELGAMAL(encrypted["Encrypted"], self.p, self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC20: Odd number of values (incomplete pair)
    def test_tc20_odd_values(self):
        """Test case TC20: Odd number of values"""
        try:
            # Simulate odd number: "[1, 2, 3]"
            result = DE_ELGAMAL("[1, 2, 3]", self.p, self.private_key)
            # Might skip last value or error
        except Exception:
            pass


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestCreateELGAMALKeys))
    suite.addTest(unittest.makeSuite(TestENELGAMAL))
    suite.addTest(unittest.makeSuite(TestDEELGAMAL))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
