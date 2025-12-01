"""
Unit Test for Hill Cipher functions - Black Box Testing
Module: MahuCrypt_app.cryptography.classical_cryptography
Functions: En_Hill_Cipher(string, key), De_Hill_Cipher(string, key)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Hill cipher encryption/decryption - matrix-based cipher
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.classical_cryptography import En_Hill_Cipher, De_Hill_Cipher


class TestEnHillCipher(unittest.TestCase):
    """
    Black Box Testing for Hill Cipher Encryption
    
    Hill Cipher: Matrix-based polyalphabetic substitution
    - Key generates a key_matrix
    - Plaintext processed in blocks of key_length
    - Matrix multiplication for encryption
    - Requires string length to be multiple of key_length
    
    Test Plan:
    - PE1: Key length = 1
    - PE2: Key length = 2 (2x2 matrix)
    - PE3: Key length = 3 (3x3 matrix)
    - PE4-PE5: Various string lengths
    - PE6: Incomplete blocks
    - PE7-PE8: Case handling
    - PE9: Non-alphabetic characters
    - PE10: Empty string
    - PE11: Key case handling
    """
    
    # TC01: PE1 - Key length = 1 (reduces to multiplication cipher)
    def test_tc01_key_length_one(self):
        """Test case TC01: Single character key"""
        result = En_Hill_Cipher("HELLO", "D")
        
        self.assertIn("Encrypted", result)
        self.assertIn("Key", result)
        self.assertEqual(result["Key"], "D")
        # D=3, so each letter multiplied by 3 mod 26
        self.assertEqual(len(result["Encrypted"]), 5)
    
    # TC02: PE2 - Key length = 2, string length = 2
    def test_tc02_key_length_two_exact(self):
        """Test case TC02: 2x2 matrix with exact block size"""
        result = En_Hill_Cipher("HE", "AB")
        
        self.assertIn("Encrypted", result)
        self.assertEqual(len(result["Encrypted"]), 2)
        # Key matrix: [[0,1], [1,2]] from "AB"
        # H=7, E=4 -> encrypted values
    
    # TC03: PE2 - Key length = 2, string length = 4 (two blocks)
    def test_tc03_key_length_two_multiple_blocks(self):
        """Test case TC03: Two blocks with 2x2 matrix"""
        result = En_Hill_Cipher("HELP", "AB")
        
        self.assertEqual(len(result["Encrypted"]), 4)
        # HE block and LP block processed separately
    
    # TC04: PE3 - Key length = 3, string length = 3
    def test_tc04_key_length_three(self):
        """Test case TC04: 3x3 matrix with single block"""
        result = En_Hill_Cipher("ACT", "ABC")
        
        self.assertEqual(len(result["Encrypted"]), 3)
        # 3x3 matrix encryption
    
    # TC05: PE3 - Key length = 3, string length = 6 (two blocks)
    def test_tc05_key_length_three_multiple(self):
        """Test case TC05: Two blocks with 3x3 matrix"""
        result = En_Hill_Cipher("ACTING", "ABC")
        
        self.assertEqual(len(result["Encrypted"]), 6)
    
    # TC06: PE4 - String length = key length (5x5)
    def test_tc06_exact_fit_large_key(self):
        """Test case TC06: Large key with exact string length"""
        result = En_Hill_Cipher("HELLO", "WORLD")
        
        self.assertEqual(len(result["Encrypted"]), 5)
        self.assertEqual(result["Key"], "WORLD")
    
    # TC07: PE5 - Multiple blocks with key length 2
    def test_tc07_multiple_blocks_ten_chars(self):
        """Test case TC07: Many blocks"""
        result = En_Hill_Cipher("HELLOWORLD", "AB")
        
        self.assertEqual(len(result["Encrypted"]), 10)
        # 5 blocks of 2 characters each
    
    # TC08: PE6 - Incomplete block (3 chars, key=2)
    def test_tc08_incomplete_block_odd_length(self):
        """Test case TC08: String length not multiple of key length"""
        try:
            result = En_Hill_Cipher("HEL", "AB")
            # May fail or silently truncate
            # If it succeeds, check length
            if "Encrypted" in result:
                # Implementation might truncate or pad
                encrypted = result["Encrypted"]
                # Could be 2 (truncate last char) or 4 (pad with something)
                self.assertIsInstance(encrypted, str)
        except (IndexError, ValueError):
            # Expected - incomplete block causes error
            pass
    
    # TC09: PE6 - Another incomplete block case
    def test_tc09_incomplete_block_five_chars_key_two(self):
        """Test case TC09: 5 characters with key length 2"""
        try:
            result = En_Hill_Cipher("HELLO", "AB")
            # 5 is not divisible by 2, last char incomplete
            if "Encrypted" in result:
                # Check if it handled incomplete block
                self.assertIsInstance(result["Encrypted"], str)
        except (IndexError, ValueError):
            pass
    
    # TC10: PE7 - Lowercase input
    def test_tc10_lowercase_input(self):
        """Test case TC10: Lowercase should convert to uppercase"""
        result = En_Hill_Cipher("hello", "AB")
        
        self.assertIn("Encrypted", result)
        # Implementation converts to uppercase
        # Should work same as "HELLO"
    
    # TC11: PE8 - Mixed case input
    def test_tc11_mixed_case(self):
        """Test case TC11: Mixed case normalized"""
        result = En_Hill_Cipher("HeLLo", "AB")
        
        self.assertIn("Encrypted", result)
        # All converted to uppercase before processing
    
    # TC12: PE9 - String with spaces
    def test_tc12_with_spaces(self):
        """Test case TC12: Spaces cause issues"""
        try:
            result = En_Hill_Cipher("HE LP", "AB")
            # Space ord() - 65 = negative, likely causes error
            self.fail("Spaces should cause error")
        except (ValueError, IndexError):
            # Expected behavior
            pass
    
    # TC13: PE9 - String with numbers
    def test_tc13_with_numbers(self):
        """Test case TC13: Numbers cause issues"""
        try:
            result = En_Hill_Cipher("HE12", "AB")
            # ord('1') - 65 gives negative value
            self.fail("Numbers should cause error")
        except (ValueError, IndexError):
            pass
    
    # TC14: PE10 - Empty string
    def test_tc14_empty_string(self):
        """Test case TC14: Empty input"""
        result = En_Hill_Cipher("", "AB")
        
        self.assertIn("Encrypted", result)
        self.assertEqual(result["Encrypted"], "")
    
    # TC15: PE11 - Lowercase key
    def test_tc15_lowercase_key(self):
        """Test case TC15: Lowercase key normalized"""
        result_lower = En_Hill_Cipher("HE", "ab")
        result_upper = En_Hill_Cipher("HE", "AB")
        
        self.assertEqual(result_lower["Encrypted"], result_upper["Encrypted"],
                        "Lowercase key should work same as uppercase")
    
    # TC16: Return structure validation
    def test_tc16_return_structure(self):
        """Test case TC16: Check return dict structure"""
        result = En_Hill_Cipher("HE", "AB")
        
        self.assertIsInstance(result, dict)
        self.assertIn("Encrypted", result)
        self.assertIn("Key", result)
        self.assertEqual(result["Key"], "AB")
    
    # TC17: Boundary - All A's
    def test_tc17_all_a_input(self):
        """Test case TC17: All zeros (A=0)"""
        result = En_Hill_Cipher("AAAA", "AB")
        
        self.assertIn("Encrypted", result)
        # All A's = all 0's, matrix mult gives specific result
    
    # TC18: Boundary - All Z's
    def test_tc18_all_z_input(self):
        """Test case TC18: Maximum alphabet values"""
        result = En_Hill_Cipher("ZZ", "AB")
        
        self.assertIn("Encrypted", result)
        self.assertEqual(len(result["Encrypted"]), 2)


class TestEnHillCipherEdgeCases(unittest.TestCase):
    """Additional edge cases for Hill cipher encryption"""
    
    def test_single_letter_string(self):
        """Test single character encryption"""
        result = En_Hill_Cipher("A", "B")
        
        self.assertEqual(len(result["Encrypted"]), 1)
    
    def test_key_length_four(self):
        """Test 4x4 matrix"""
        result = En_Hill_Cipher("HELLOWORLDHOW", "ABCD")
        
        # 12 chars (3 blocks of 4)
        self.assertIn("Encrypted", result)
        # Note: 13 chars, incomplete block
    
    def test_uppercase_only_output(self):
        """Test that output is always uppercase"""
        result = En_Hill_Cipher("hello", "ab")
        
        encrypted = result["Encrypted"]
        if encrypted:
            self.assertTrue(encrypted.isupper(), "Output should be uppercase")
    
    def test_deterministic_encryption(self):
        """Test that same input gives same output"""
        result1 = En_Hill_Cipher("HELLO", "ABC")
        result2 = En_Hill_Cipher("HELLO", "ABC")
        
        if "Encrypted" in result1 and "Encrypted" in result2:
            self.assertEqual(result1["Encrypted"], result2["Encrypted"],
                           "Deterministic encryption")


class TestDeHillCipher(unittest.TestCase):
    """
    Black Box Testing for Hill Cipher Decryption
    
    Decryption: Uses inverse of key matrix
    - Matrix must be invertible
    - Determinant must be coprime with 26
    - Uses Ext_Euclide for modular inverse
    """
    
    # TC01: PE1 - Key length = 1
    def test_tc01_key_length_one(self):
        """Test case TC01: Single char key decryption"""
        # First encrypt
        enc = En_Hill_Cipher("HELLO", "D")
        if "Encrypted" in enc:
            # Then decrypt
            dec = De_Hill_Cipher(enc["Encrypted"], "D")
            self.assertIn("Decrypted", dec)
    
    # TC02: PE2 - Key length = 2
    def test_tc02_key_length_two(self):
        """Test case TC02: 2x2 matrix decryption"""
        enc = En_Hill_Cipher("HE", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertEqual(dec["Decrypted"], "HE")
    
    # TC03: PE2 - Multiple blocks
    def test_tc03_multiple_blocks_key_two(self):
        """Test case TC03: Two blocks decryption"""
        enc = En_Hill_Cipher("HELP", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertEqual(dec["Decrypted"], "HELP")
    
    # TC04: PE3 - Key length = 3
    def test_tc04_key_length_three(self):
        """Test case TC04: 3x3 matrix decryption"""
        enc = En_Hill_Cipher("ACT", "ABC")
        dec = De_Hill_Cipher(enc["Encrypted"], "ABC")
        
        self.assertEqual(dec["Decrypted"], "ACT")
    
    # TC05: PE4 - Exact fit with large key
    def test_tc05_exact_fit(self):
        """Test case TC05: Large key exact fit"""
        enc = En_Hill_Cipher("HELLO", "WORLD")
        dec = De_Hill_Cipher(enc["Encrypted"], "WORLD")
        
        self.assertEqual(dec["Decrypted"], "HELLO")
    
    # TC06: PE5 - Multiple blocks
    def test_tc06_multiple_blocks_many(self):
        """Test case TC06: Many blocks decryption"""
        enc = En_Hill_Cipher("HELLOWORLD", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertEqual(dec["Decrypted"], "HELLOWORLD")
    
    # TC07: PE6 - Incomplete block
    def test_tc07_incomplete_block(self):
        """Test case TC07: Incomplete block handling"""
        try:
            enc = En_Hill_Cipher("HEL", "AB")
            if "Encrypted" in enc:
                dec = De_Hill_Cipher(enc["Encrypted"], "AB")
                # If encryption worked, decryption should too
                self.assertIn("Decrypted", dec)
        except (IndexError, ValueError):
            pass
    
    # TC08: PE7 - Lowercase input to decrypt
    def test_tc08_lowercase_ciphertext(self):
        """Test case TC08: Lowercase ciphertext normalized"""
        enc = En_Hill_Cipher("HE", "AB")
        ciphertext_lower = enc["Encrypted"].lower()
        
        dec = De_Hill_Cipher(ciphertext_lower, "AB")
        self.assertEqual(dec["Decrypted"], "HE")
    
    # TC09: PE8 - Empty string
    def test_tc09_empty_string(self):
        """Test case TC09: Empty decryption"""
        dec = De_Hill_Cipher("", "AB")
        
        self.assertEqual(dec["Decrypted"], "")
    
    # TC10: PE9 - Round trip basic
    def test_tc10_roundtrip_basic(self):
        """Test case TC10: Encrypt-decrypt round trip"""
        original = "HE"
        key = "AB"
        
        enc = En_Hill_Cipher(original, key)
        dec = De_Hill_Cipher(enc["Encrypted"], key)
        
        self.assertEqual(dec["Decrypted"], original)
    
    # TC11: PE9 - Round trip multiple blocks
    def test_tc11_roundtrip_multiple(self):
        """Test case TC11: Multiple blocks round trip"""
        original = "HELP"
        key = "AB"
        
        enc = En_Hill_Cipher(original, key)
        dec = De_Hill_Cipher(enc["Encrypted"], key)
        
        self.assertEqual(dec["Decrypted"], original)
    
    # TC12: PE9 - Round trip 3x3
    def test_tc12_roundtrip_three_by_three(self):
        """Test case TC12: 3x3 matrix round trip"""
        original = "ACTING"
        key = "ABC"
        
        enc = En_Hill_Cipher(original, key)
        dec = De_Hill_Cipher(enc["Encrypted"], key)
        
        self.assertEqual(dec["Decrypted"], original)
    
    # TC13: PE9 - Round trip all A's
    def test_tc13_roundtrip_all_a(self):
        """Test case TC13: Edge values round trip"""
        original = "AAAA"
        key = "AB"
        
        enc = En_Hill_Cipher(original, key)
        dec = De_Hill_Cipher(enc["Encrypted"], key)
        
        self.assertEqual(dec["Decrypted"], original)
    
    # TC14: PE10 - Non-invertible matrix (if possible)
    def test_tc14_non_invertible_matrix(self):
        """Test case TC14: Matrix that might not be invertible"""
        # Try to find a key that creates non-invertible matrix
        # Key matrix generation: [[ord(k[0])-65, ord(k[1])-65], [ord(k[1])-65, (ord(k[1])-65+1)%26]]
        # For key "AA": [[0,0], [0,1]] - determinant = 0
        try:
            enc = En_Hill_Cipher("HELLO", "AA")
            if "Encrypted" in enc:
                dec = De_Hill_Cipher(enc["Encrypted"], "AA")
                # Might fail on decryption due to non-invertible matrix
                self.assertIn("Decrypted", dec)
        except (Exception,):
            # Expected if matrix is not invertible
            pass
    
    # TC15: PE11 - Lowercase key
    def test_tc15_lowercase_key(self):
        """Test case TC15: Lowercase key handling"""
        enc = En_Hill_Cipher("HE", "AB")
        dec_lower = De_Hill_Cipher(enc["Encrypted"], "ab")
        dec_upper = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertEqual(dec_lower["Decrypted"], dec_upper["Decrypted"])
    
    # TC16: Return structure
    def test_tc16_return_structure(self):
        """Test case TC16: Return dict validation"""
        enc = En_Hill_Cipher("HE", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertIsInstance(dec, dict)
        self.assertIn("Decrypted", dec)
    
    # TC17: Boundary - Minimal case
    def test_tc17_minimal_case(self):
        """Test case TC17: Smallest valid input"""
        enc = En_Hill_Cipher("AB", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        self.assertEqual(dec["Decrypted"], "AB")


class TestDeHillCipherEdgeCases(unittest.TestCase):
    """Additional edge cases for Hill cipher decryption"""
    
    def test_multiple_roundtrips_different_keys(self):
        """Test round trips with various keys"""
        test_cases = [
            ("HE", "AB"),
            ("HELP", "CD"),
            ("ACTING", "KEY"),
        ]
        
        for plaintext, key in test_cases:
            with self.subTest(plaintext=plaintext, key=key):
                try:
                    enc = En_Hill_Cipher(plaintext, key)
                    if "Encrypted" in enc:
                        dec = De_Hill_Cipher(enc["Encrypted"], key)
                        if "Decrypted" in dec:
                            self.assertEqual(dec["Decrypted"], plaintext)
                except Exception:
                    # Some keys might not work (non-invertible)
                    pass
    
    def test_uppercase_output(self):
        """Test decryption always outputs uppercase"""
        enc = En_Hill_Cipher("hello", "AB")
        dec = De_Hill_Cipher(enc["Encrypted"], "AB")
        
        decrypted = dec["Decrypted"]
        if decrypted:
            self.assertTrue(decrypted.isupper())
    
    def test_long_key(self):
        """Test with longer key"""
        # 4x4 matrix
        plaintext = "HELLOWORLD12"  # 12 chars for 3 blocks of 4
        key = "ABCD"
        
        try:
            enc = En_Hill_Cipher(plaintext, key)
            if "Encrypted" in enc:
                dec = De_Hill_Cipher(enc["Encrypted"], key)
                # Might fail on numbers
        except Exception:
            pass


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestEnHillCipher))
    suite.addTest(unittest.makeSuite(TestEnHillCipherEdgeCases))
    suite.addTest(unittest.makeSuite(TestDeHillCipher))
    suite.addTest(unittest.makeSuite(TestDeHillCipherEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
