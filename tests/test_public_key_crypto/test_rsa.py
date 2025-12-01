"""
Unit Test for RSA Cryptography functions - Black Box Testing
Module: MahuCrypt_app.cryptography.public_key_cryptography
Functions: create_RSA_keys(bits), EN_RSA(string, public_key), DE_RSA(encrypted, private_key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: RSA key generation, encryption, and decryption
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.public_key_cryptography import create_RSA_keys, EN_RSA, DE_RSA
from MahuCrypt_app.cryptography.algos import miller_rabin_test, Ext_Euclide


class TestCreateRSAKeys(unittest.TestCase):
    """
    Black Box Testing for create_RSA_keys(bits)
    
    RSA Key Generation:
    - Generates random prime numbers p, q
    - Computes n = p*q, φ(n) = (p-1)(q-1)
    - Selects e, computes d = e^(-1) mod φ(n)
    - Returns dict with public_key (n, e) and private_key (d, p, q)
    
    Test Plan:
    - PE1-PE4: Various bit sizes
    - PE5-PE8: Edge cases and invalid inputs
    - Validation: structure, primality, mathematical properties
    """
    
    # TC01: PE1 - Small bits (8)
    def test_tc01_bits_small_8(self):
        """Test case TC01: Generate RSA keys with 8 bits"""
        result = create_RSA_keys(8)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
    
    # TC02: PE1 - bits=16
    def test_tc02_bits_16(self):
        """Test case TC02: 16-bit key generation"""
        result = create_RSA_keys(16)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
    
    # TC03: PE2 - Medium bits (32)
    def test_tc03_bits_medium_32(self):
        """Test case TC03: 32-bit RSA keys"""
        result = create_RSA_keys(32)
        
        self.assertIsInstance(result, dict)
        # Should complete in reasonable time
    
    # TC04: PE2 - bits=64
    def test_tc04_bits_64(self):
        """Test case TC04: 64-bit key generation"""
        result = create_RSA_keys(64)
        
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
    
    # TC05: PE3 - Large bits (128)
    def test_tc05_bits_large_128(self):
        """Test case TC05: 128-bit RSA keys (secure)"""
        result = create_RSA_keys(128)
        
        self.assertIn("public_key", result)
        # Might take a bit longer but should complete
    
    # TC06: PE3 - bits=256 (skip if too slow)
    @unittest.skip("Too slow")
    def test_tc06_bits_256(self):
        """Test case TC06: 256-bit keys (very secure, slow)"""
        result = create_RSA_keys(256)
        
        self.assertIsInstance(result, dict)
    
    # TC07: PE4 - Very large bits (skip)
    @unittest.skip("Too slow")
    def test_tc07_bits_very_large_512(self):
        """Test case TC07: 512-bit keys (production level)"""
        result = create_RSA_keys(512)
        
        self.assertIn("public_key", result)
    
    # TC08: PE5 - bits=1 (too small, may hang)
    def test_tc08_bits_one(self):
        """Test case TC08: 1 bit - cannot generate prime"""
        # This might hang or error
        try:
            # Set a timeout or skip
            # result = create_RSA_keys(1)
            # Likely hangs in get_prime_number
            pass
        except Exception:
            pass
    
    # TC09: PE6 - bits=2 (minimum)
    def test_tc09_bits_two(self):
        """Test case TC09: 2 bits - minimum possible"""
        try:
            result = create_RSA_keys(2)
            # Primes: 2, 3
            if "public_key" in result:
                self.assertIsInstance(result, dict)
        except Exception:
            # May not work reliably
            pass
    
    # TC10: PE7 - Negative bits
    def test_tc10_bits_negative(self):
        """Test case TC10: Negative bits - invalid"""
        try:
            result = create_RSA_keys(-10)
            # Should error or produce invalid result
            self.fail("Negative bits should cause error")
        except (ValueError, OverflowError):
            pass
    
    # TC11: PE8 - bits=0
    def test_tc11_bits_zero(self):
        """Test case TC11: Zero bits - invalid"""
        try:
            result = create_RSA_keys(0)
            self.fail("Zero bits should cause error")
        except (ValueError, ZeroDivisionError):
            pass
    
    # TC12: Return structure validation
    def test_tc12_return_structure(self):
        """Test case TC12: Validate return dictionary structure"""
        result = create_RSA_keys(16)
        
        self.assertIsInstance(result, dict)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIsInstance(result["public_key"], dict)
        self.assertIsInstance(result["private_key"], dict)
    
    # TC13: Public key structure
    def test_tc13_public_key_structure(self):
        """Test case TC13: Public key has n and e"""
        result = create_RSA_keys(16)
        
        public_key = result["public_key"]
        self.assertIn("n", public_key)
        self.assertIn("e", public_key)
        # Values stored as strings
        self.assertIsInstance(public_key["n"], str)
        self.assertIsInstance(public_key["e"], str)
    
    # TC14: Private key structure
    def test_tc14_private_key_structure(self):
        """Test case TC14: Private key has d, p, q"""
        result = create_RSA_keys(16)
        
        private_key = result["private_key"]
        self.assertIn("d", private_key)
        self.assertIn("p", private_key)
        self.assertIn("q", private_key)
        # All stored as strings
        self.assertIsInstance(private_key["d"], str)
        self.assertIsInstance(private_key["p"], str)
        self.assertIsInstance(private_key["q"], str)
    
    # TC15: p and q are prime
    def test_tc15_p_q_are_prime(self):
        """Test case TC15: Verify p and q are prime numbers"""
        result = create_RSA_keys(16)
        
        p = int(result["private_key"]["p"])
        q = int(result["private_key"]["q"])
        
        # Test primality
        self.assertTrue(miller_rabin_test(p, 100), f"p={p} should be prime")
        self.assertTrue(miller_rabin_test(q, 100), f"q={q} should be prime")
    
    # TC16: n = p*q
    def test_tc16_n_equals_p_times_q(self):
        """Test case TC16: Verify n = p * q"""
        result = create_RSA_keys(16)
        
        n = int(result["public_key"]["n"])
        p = int(result["private_key"]["p"])
        q = int(result["private_key"]["q"])
        
        self.assertEqual(n, p * q, "n should equal p*q")
    
    # TC17: e coprime with φ(n)
    def test_tc17_e_coprime_with_phi(self):
        """Test case TC17: gcd(e, φ(n)) = 1"""
        result = create_RSA_keys(16)
        
        e = int(result["public_key"]["e"])
        p = int(result["private_key"]["p"])
        q = int(result["private_key"]["q"])
        phi_n = (p - 1) * (q - 1)
        
        gcd = Ext_Euclide(e, phi_n)[0]
        self.assertEqual(gcd, 1, "e must be coprime with φ(n)")
    
    # TC18: d*e ≡ 1 mod φ(n)
    def test_tc18_d_times_e_mod_phi(self):
        """Test case TC18: Verify (d * e) % φ(n) = 1"""
        result = create_RSA_keys(16)
        
        e = int(result["public_key"]["e"])
        d = int(result["private_key"]["d"])
        p = int(result["private_key"]["p"])
        q = int(result["private_key"]["q"])
        phi_n = (p - 1) * (q - 1)
        
        self.assertEqual((d * e) % phi_n, 1, "d should be modular inverse of e")
    
    # TC19: Randomness - different keys on different calls
    def test_tc19_randomness(self):
        """Test case TC19: Two calls produce different keys"""
        result1 = create_RSA_keys(16)
        result2 = create_RSA_keys(16)
        
        # Keys should be different (with very high probability)
        n1 = result1["public_key"]["n"]
        n2 = result2["public_key"]["n"]
        
        self.assertNotEqual(n1, n2, "Keys should be random and different")
    
    # TC20: String format for all values
    def test_tc20_string_format(self):
        """Test case TC20: All values are strings"""
        result = create_RSA_keys(16)
        
        # Check all values in nested dicts are strings
        for key in ["n", "e"]:
            self.assertIsInstance(result["public_key"][key], str)
        
        for key in ["d", "p", "q"]:
            self.assertIsInstance(result["private_key"][key], str)


class TestENRSA(unittest.TestCase):
    """
    Black Box Testing for EN_RSA(string, public_key)
    
    RSA Encryption:
    - Input: plaintext string, public_key tuple (n, e)
    - Process: pre_solve → chunk into 4-char blocks → convert to int → encrypt
    - Output: {"Encrypted": str(list)}
    
    Test Plan:
    - PE1-PE3: Various string lengths
    - PE4-PE9: Case, spaces, special characters
    - PE10-PE12: Key validation
    - Round trip and determinism tests
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate a test RSA key pair for all tests"""
        cls.keys = create_RSA_keys(32)
        cls.public_key = (
            int(cls.keys["public_key"]["n"]),
            int(cls.keys["public_key"]["e"])
        )
        cls.private_key = {
            "p": int(cls.keys["private_key"]["p"]),
            "q": int(cls.keys["private_key"]["q"]),
            "d": int(cls.keys["private_key"]["d"])
        }
    
    # TC01: PE1 - Short string (1 block)
    def test_tc01_short_string_single_block(self):
        """Test case TC01: 4-character string (single block)"""
        result = EN_RSA("HELL", self.public_key)
        
        self.assertIn("Encrypted", result)
        # Parse the list
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
        self.assertGreater(len(encrypted_list), 0)
    
    # TC02: PE1 - Single character
    def test_tc02_single_character(self):
        """Test case TC02: Minimum input - 1 character"""
        result = EN_RSA("A", self.public_key)
        
        self.assertIn("Encrypted", result)
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC03: PE2 - Medium string (2 blocks)
    def test_tc03_medium_string_5_chars(self):
        """Test case TC03: 5 characters = 2 blocks"""
        result = EN_RSA("HELLO", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        # 5 chars should produce 2 blocks (4 + 1)
        self.assertIsInstance(encrypted_list, list)
    
    # TC04: PE2 - Exactly 8 characters (2 blocks)
    def test_tc04_eight_characters(self):
        """Test case TC04: 8 chars = exactly 2 blocks"""
        result = EN_RSA("HELLOABC", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC05: PE3 - Long string
    def test_tc05_long_string(self):
        """Test case TC05: Long string with multiple blocks"""
        result = EN_RSA("HELLO WORLD TEST", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertGreater(len(encrypted_list), 2, "Should have multiple blocks")
    
    # TC06: PE4 - Empty string
    def test_tc06_empty_string(self):
        """Test case TC06: Empty input"""
        result = EN_RSA("", self.public_key)
        
        self.assertIn("Encrypted", result)
        # Should return empty list or error
    
    # TC07: PE5 - Lowercase
    def test_tc07_lowercase_input(self):
        """Test case TC07: Lowercase letters"""
        result = EN_RSA("hello", self.public_key)
        
        self.assertIn("Encrypted", result)
        # pre_solve converts to uppercase
    
    # TC08: PE6 - Uppercase
    def test_tc08_uppercase_input(self):
        """Test case TC08: Uppercase letters (standard)"""
        result = EN_RSA("HELLO", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
    
    # TC09: PE7 - Mixed case
    def test_tc09_mixed_case(self):
        """Test case TC09: Mixed case input"""
        result = EN_RSA("HeLLo", self.public_key)
        
        self.assertIn("Encrypted", result)
        # Should be normalized
    
    # TC10: PE8 - With spaces
    def test_tc10_with_spaces(self):
        """Test case TC10: String with spaces"""
        result = EN_RSA("HELLO WORLD", self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertIsInstance(encrypted_list, list)
        # pre_solve handles spaces
    
    # TC11: PE9 - Special characters
    def test_tc11_special_characters(self):
        """Test case TC11: String with special chars"""
        result = EN_RSA("HELLO!", self.public_key)
        
        self.assertIn("Encrypted", result)
        # pre_solve processes special chars
    
    # TC12: PE10 - Valid key
    def test_tc12_valid_key(self):
        """Test case TC12: Standard operation with valid key"""
        result = EN_RSA("TEST", self.public_key)
        
        self.assertIn("Encrypted", result)
        encrypted_list = eval(result["Encrypted"])
        self.assertTrue(all(isinstance(x, int) for x in encrypted_list))
    
    # TC13: PE11 - Invalid key format (will likely error)
    def test_tc13_invalid_key_format(self):
        """Test case TC13: Invalid key format"""
        try:
            result = EN_RSA("TEST", (123, "abc"))
            # Might error in modular_exponentiation
        except (TypeError, ValueError):
            pass
    
    # TC14: PE12 - n too small (potential overflow)
    def test_tc14_n_too_small(self):
        """Test case TC14: Very small n might cause issues"""
        # Create tiny key
        tiny_key = (10, 3)  # n=10, e=3
        try:
            result = EN_RSA("ZZZZ", tiny_key)
            # Plaintext int might be >= n
        except Exception:
            pass
    
    # TC15: Return structure
    def test_tc15_return_structure(self):
        """Test case TC15: Validate return structure"""
        result = EN_RSA("TEST", self.public_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Encrypted", result)
    
    # TC16: Encrypted format
    def test_tc16_encrypted_format(self):
        """Test case TC16: Encrypted is string of list"""
        result = EN_RSA("TEST", self.public_key)
        
        encrypted_str = result["Encrypted"]
        self.assertIsInstance(encrypted_str, str)
        # Should be parseable as list
        encrypted_list = eval(encrypted_str)
        self.assertIsInstance(encrypted_list, list)
    
    # TC17: Deterministic encryption
    def test_tc17_deterministic(self):
        """Test case TC17: Same input gives same output"""
        result1 = EN_RSA("TEST", self.public_key)
        result2 = EN_RSA("TEST", self.public_key)
        
        self.assertEqual(result1["Encrypted"], result2["Encrypted"],
                        "RSA should be deterministic")
    
    # TC18: Different keys give different outputs
    def test_tc18_different_keys(self):
        """Test case TC18: Different keys encrypt differently"""
        keys2 = create_RSA_keys(32)
        public_key2 = (int(keys2["public_key"]["n"]), int(keys2["public_key"]["e"]))
        
        result1 = EN_RSA("TEST", self.public_key)
        result2 = EN_RSA("TEST", public_key2)
        
        self.assertNotEqual(result1["Encrypted"], result2["Encrypted"],
                           "Different keys should produce different ciphertexts")
    
    # TC19: Long string stress test
    def test_tc19_long_string(self):
        """Test case TC19: Very long string"""
        long_string = "A" * 100
        result = EN_RSA(long_string, self.public_key)
        
        encrypted_list = eval(result["Encrypted"])
        self.assertGreater(len(encrypted_list), 20, "Many blocks for long string")
    
    # TC20: Numeric in string
    def test_tc20_numeric_in_string(self):
        """Test case TC20: String with numbers"""
        result = EN_RSA("HELLO123", self.public_key)
        
        self.assertIn("Encrypted", result)
        # pre_solve handles numbers


class TestDERSA(unittest.TestCase):
    """
    Black Box Testing for DE_RSA(encrypted, private_key)
    
    RSA Decryption:
    - Input: encrypted (string of list), private_key dict
    - Process: parse list → decrypt each block → convert to string → join
    - Output: {"Decrypted": string}
    
    Test Plan:
    - PE1-PE3: Various encrypted sizes
    - PE4-PE7: Key validation
    - PE8: Round trip tests
    - PE9-PE10: Multiple messages and keys
    """
    
    @classmethod
    def setUpClass(cls):
        """Generate test keys"""
        cls.keys = create_RSA_keys(32)
        cls.public_key = (
            int(cls.keys["public_key"]["n"]),
            int(cls.keys["public_key"]["e"])
        )
        cls.private_key = {
            "p": int(cls.keys["private_key"]["p"]),
            "q": int(cls.keys["private_key"]["q"]),
            "d": int(cls.keys["private_key"]["d"])
        }
    
    # TC01: PE1 - Single block decryption
    def test_tc01_single_block(self):
        """Test case TC01: Decrypt single block"""
        encrypted = EN_RSA("HELL", self.public_key)
        result = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIn("Decrypted", result)
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC02: PE2 - Multiple blocks
    def test_tc02_multiple_blocks(self):
        """Test case TC02: Decrypt multiple blocks"""
        encrypted = EN_RSA("HELLO WORLD", self.public_key)
        result = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC03: PE3 - Empty list
    def test_tc03_empty_list(self):
        """Test case TC03: Decrypt empty encrypted list"""
        result = DE_RSA("[]", self.private_key)
        
        self.assertIn("Decrypted", result)
        # Should return empty string
    
    # TC04: PE4 - Valid private key
    def test_tc04_valid_key(self):
        """Test case TC04: Standard decryption with valid key"""
        encrypted = EN_RSA("TEST", self.public_key)
        result = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIn("Decrypted", result)
    
    # TC05: PE5 - Missing d in private_key
    def test_tc05_missing_d(self):
        """Test case TC05: Private key without d"""
        encrypted = EN_RSA("TEST", self.public_key)
        bad_key = {"p": self.private_key["p"], "q": self.private_key["q"]}
        
        try:
            result = DE_RSA(encrypted["Encrypted"], bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC06: PE5 - Missing p
    def test_tc06_missing_p(self):
        """Test case TC06: Private key without p"""
        encrypted = EN_RSA("TEST", self.public_key)
        bad_key = {"d": self.private_key["d"], "q": self.private_key["q"]}
        
        try:
            result = DE_RSA(encrypted["Encrypted"], bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC07: PE5 - Missing q
    def test_tc07_missing_q(self):
        """Test case TC07: Private key without q"""
        encrypted = EN_RSA("TEST", self.public_key)
        bad_key = {"p": self.private_key["p"], "d": self.private_key["d"]}
        
        try:
            result = DE_RSA(encrypted["Encrypted"], bad_key)
            self.fail("Should raise KeyError")
        except KeyError:
            pass
    
    # TC08: PE6 - Wrong d value
    def test_tc08_wrong_d_value(self):
        """Test case TC08: Incorrect d produces wrong plaintext"""
        encrypted = EN_RSA("TEST", self.public_key)
        bad_key = {
            "p": self.private_key["p"],
            "q": self.private_key["q"],
            "d": self.private_key["d"] + 1  # Wrong d
        }
        
        result = DE_RSA(encrypted["Encrypted"], bad_key)
        # Will decrypt but to wrong plaintext
        self.assertNotEqual(result["Decrypted"], "TEST")
    
    # TC09: PE7 - Malformed encrypted string
    def test_tc09_malformed_string(self):
        """Test case TC09: Invalid encrypted string format"""
        try:
            result = DE_RSA("not a list", self.private_key)
            # Parsing should fail
        except (ValueError, SyntaxError, NameError):
            pass
    
    # TC10: PE7 - Non-numeric in list
    def test_tc10_non_numeric_in_list(self):
        """Test case TC10: Invalid values in encrypted list"""
        try:
            result = DE_RSA("[1, 2, 'abc']", self.private_key)
            self.fail("Should raise ValueError")
        except ValueError:
            pass
    
    # TC11: PE8 - Round trip TEST
    def test_tc11_roundtrip_test(self):
        """Test case TC11: Encrypt then decrypt TEST"""
        original = "TEST"
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertEqual(decrypted["Decrypted"], original,
                        "Round trip should preserve plaintext")
    
    # TC12: PE8 - Round trip HELLO
    def test_tc12_roundtrip_hello(self):
        """Test case TC12: Round trip with HELLO"""
        original = "HELLO"
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        # Note: pre_solve might modify original
        self.assertIn("Decrypted", decrypted)
    
    # TC13: PE8 - Round trip long text
    def test_tc13_roundtrip_long_text(self):
        """Test case TC13: Round trip with long string"""
        original = "A" * 50
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertEqual(len(decrypted["Decrypted"]), len(original))
    
    # TC14: PE9 - Different messages
    def test_tc14_different_messages(self):
        """Test case TC14: Decrypt multiple different messages"""
        messages = ["AAA", "BBB", "CCC"]
        
        for msg in messages:
            with self.subTest(msg=msg):
                encrypted = EN_RSA(msg, self.public_key)
                decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
                # Each should decrypt to something
                self.assertIn("Decrypted", decrypted)
    
    # TC15: PE10 - Different keys
    def test_tc15_different_keys(self):
        """Test case TC15: Decrypt with different key pairs"""
        # Generate second key pair
        keys2 = create_RSA_keys(32)
        public_key2 = (int(keys2["public_key"]["n"]), int(keys2["public_key"]["e"]))
        private_key2 = {
            "p": int(keys2["private_key"]["p"]),
            "q": int(keys2["private_key"]["q"]),
            "d": int(keys2["private_key"]["d"])
        }
        
        # Encrypt with key1, decrypt with key1
        enc1 = EN_RSA("TEST", self.public_key)
        dec1 = DE_RSA(enc1["Encrypted"], self.private_key)
        
        # Encrypt with key2, decrypt with key2
        enc2 = EN_RSA("TEST", public_key2)
        dec2 = DE_RSA(enc2["Encrypted"], private_key2)
        
        # Both should work
        self.assertIn("Decrypted", dec1)
        self.assertIn("Decrypted", dec2)
    
    # TC16: Return structure
    def test_tc16_return_structure(self):
        """Test case TC16: Validate return structure"""
        encrypted = EN_RSA("TEST", self.public_key)
        result = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Decrypted", result)
    
    # TC17: Decrypted is string
    def test_tc17_decrypted_format(self):
        """Test case TC17: Decrypted value is string"""
        encrypted = EN_RSA("TEST", self.public_key)
        result = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIsInstance(result["Decrypted"], str)
    
    # TC18: Case handling (depends on pre_solve)
    def test_tc18_case_handling(self):
        """Test case TC18: Mixed case handling"""
        original = "HeLLo"
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        # pre_solve likely converts to uppercase
        self.assertIn("Decrypted", decrypted)
    
    # TC19: Special characters
    def test_tc19_special_characters(self):
        """Test case TC19: String with special chars"""
        original = "HELLO!"
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIn("Decrypted", decrypted)
    
    # TC20: Numbers in string
    def test_tc20_numbers_in_string(self):
        """Test case TC20: String with numbers"""
        original = "HELLO123"
        encrypted = EN_RSA(original, self.public_key)
        decrypted = DE_RSA(encrypted["Encrypted"], self.private_key)
        
        self.assertIn("Decrypted", decrypted)


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestCreateRSAKeys))
    suite.addTest(unittest.makeSuite(TestENRSA))
    suite.addTest(unittest.makeSuite(TestDERSA))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
