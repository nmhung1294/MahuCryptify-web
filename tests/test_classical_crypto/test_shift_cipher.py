"""
Unit Test for En_Shift_Cipher function - Black Box Testing
Module: MahuCrypt_app.cryptography.classical_cryptography
Function: En_Shift_Cipher(string, shift)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Caesar cipher encryption - shift characters by a fixed amount
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.classical_cryptography import En_Shift_Cipher, De_Shift_Cipher


class TestEnShiftCipher(unittest.TestCase):
    """
    Black Box Testing for Shift Cipher Encryption (Caesar Cipher)
    
    Test Plan:
    - PE1: Shift = 0 (no encryption)
    - PE2: Small positive shift (1-12)
    - PE3: Shift = 13 (ROT13)
    - PE4: Shift = 25 (maximum in range [0,25])
    - PE5: Shift = 26 (full rotation)
    - PE6: Negative shift
    - PE7: Large shift > 26
    - PE8: Empty string
    - PE9: Lowercase letters
    - PE10: Mixed case
    - PE11: String with numbers
    - PE12: String with special characters
    - PE13: Only numbers
    - PE14: Only special characters
    - Boundary: Very long string
    """
    
    # TC01: PE1 - Shift = 0 (no encryption)
    def test_tc01_shift_zero(self):
        """Test case TC01: Shift by 0 should return unchanged string"""
        result = En_Shift_Cipher("HELLO", 0)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Encrypted", result)
        self.assertIn("Key", result)
        self.assertEqual(result["Encrypted"], "HELLO", "Shift 0 should not change string")
        self.assertEqual(result["Key"], 0)
    
    # TC02: PE2 - Small positive shift (Caesar cipher standard)
    def test_tc02_small_positive_shift(self):
        """Test case TC02: Caesar cipher with shift 3"""
        result = En_Shift_Cipher("HELLO", 3)
        
        self.assertEqual(result["Encrypted"], "KHOOR", "HELLO shifted by 3 should be KHOOR")
        self.assertEqual(result["Key"], 3)
    
    # TC03: PE3 - Shift = 13 (ROT13)
    def test_tc03_rot13(self):
        """Test case TC03: ROT13 encryption (shift 13)"""
        result = En_Shift_Cipher("HELLO", 13)
        
        self.assertEqual(result["Encrypted"], "URYYB", "HELLO with ROT13 should be URYYB")
        self.assertEqual(result["Key"], 13)
    
    # TC04: PE4 - Shift = 25 (maximum in valid range)
    def test_tc04_shift_twenty_five(self):
        """Test case TC04: Maximum shift in [0,25] range"""
        result = En_Shift_Cipher("HELLO", 25)
        
        # H(7) + 25 = 32 mod 26 = 6 = G
        # E(4) + 25 = 29 mod 26 = 3 = D
        # L(11) + 25 = 36 mod 26 = 10 = K
        # O(14) + 25 = 39 mod 26 = 13 = N
        self.assertEqual(result["Encrypted"], "GDKKN", "HELLO shifted by 25 should be GDKKN")
        self.assertEqual(result["Key"], 25)
    
    # TC05: PE5 - Shift = 26 (full rotation, should be same as 0)
    def test_tc05_shift_twenty_six(self):
        """Test case TC05: Shift 26 should complete full rotation"""
        result = En_Shift_Cipher("ABC", 26)
        
        # 26 mod 26 = 0, so should be same as original
        self.assertEqual(result["Encrypted"], "ABC", "Shift 26 should be same as shift 0")
        self.assertEqual(result["Key"], 26)
    
    # TC06: PE6 - Negative shift
    def test_tc06_negative_shift(self):
        """Test case TC06: Negative shift (backward shift)"""
        result = En_Shift_Cipher("HELLO", -3)
        
        # H(7) - 3 = 4 = E
        # E(4) - 3 = 1 = B
        # L(11) - 3 = 8 = I
        # O(14) - 3 = 11 = L
        self.assertEqual(result["Encrypted"], "EBIIL", "HELLO shifted by -3 should be EBIIL")
        self.assertEqual(result["Key"], -3)
    
    # TC07: PE7 - Large shift > 26
    def test_tc07_large_shift(self):
        """Test case TC07: Shift > 26 should wrap around (29 mod 26 = 3)"""
        result = En_Shift_Cipher("ABC", 29)
        
        # 29 mod 26 = 3, so A->D, B->E, C->F
        self.assertEqual(result["Encrypted"], "DEF", "ABC shifted by 29 should be DEF")
        self.assertEqual(result["Key"], 29)
    
    # TC08: PE8 - Empty string
    def test_tc08_empty_string(self):
        """Test case TC08: Empty string should return empty encrypted result"""
        result = En_Shift_Cipher("", 5)
        
        self.assertEqual(result["Encrypted"], "", "Empty string should return empty")
        self.assertEqual(result["Key"], 5)
    
    # TC09: PE9 - Lowercase letters
    def test_tc09_lowercase_input(self):
        """Test case TC09: Lowercase letters should be converted to uppercase"""
        result = En_Shift_Cipher("hello", 3)
        
        # Should convert to uppercase then shift
        self.assertEqual(result["Encrypted"], "KHOOR", "Lowercase should be converted and shifted")
        self.assertEqual(result["Key"], 3)
    
    # TC10: PE10 - Mixed case
    def test_tc10_mixed_case(self):
        """Test case TC10: Mixed case should all become uppercase"""
        result = En_Shift_Cipher("HeLLo", 3)
        
        self.assertEqual(result["Encrypted"], "KHOOR", "Mixed case should normalize to uppercase")
        self.assertEqual(result["Key"], 3)
    
    # TC11: PE11 - String with numbers
    def test_tc11_string_with_numbers(self):
        """Test case TC11: Numbers should remain unchanged"""
        result = En_Shift_Cipher("HELLO123", 3)
        
        self.assertEqual(result["Encrypted"], "KHOOR123", 
                        "Numbers should not be encrypted")
        self.assertEqual(result["Key"], 3)
    
    # TC12: PE12 - String with special characters
    def test_tc12_special_characters(self):
        """Test case TC12: Special characters and spaces should remain unchanged"""
        result = En_Shift_Cipher("HELLO WORLD!", 3)
        
        self.assertEqual(result["Encrypted"], "KHOOR ZRUOG!", 
                        "Spaces and punctuation should remain unchanged")
        self.assertEqual(result["Key"], 3)
    
    # TC13: PE13 - Only numbers
    def test_tc13_only_numbers(self):
        """Test case TC13: String with only numbers"""
        result = En_Shift_Cipher("12345", 5)
        
        self.assertEqual(result["Encrypted"], "12345", 
                        "Numbers-only string should remain unchanged")
        self.assertEqual(result["Key"], 5)
    
    # TC14: PE14 - Only special characters
    def test_tc14_only_special_chars(self):
        """Test case TC14: String with only special characters"""
        result = En_Shift_Cipher("!@#$%", 10)
        
        self.assertEqual(result["Encrypted"], "!@#$%", 
                        "Special characters should remain unchanged")
        self.assertEqual(result["Key"], 10)
    
    # TC15: Boundary - Very long string (performance test)
    def test_tc15_long_string(self):
        """Test case TC15: Very long string (1000 characters)"""
        long_string = "A" * 1000
        result = En_Shift_Cipher(long_string, 13)
        
        expected = "N" * 1000  # A shifted by 13 is N
        self.assertEqual(result["Encrypted"], expected, 
                        "Long string should be processed correctly")
        self.assertEqual(result["Key"], 13)
        self.assertEqual(len(result["Encrypted"]), 1000, 
                        "Output length should match input length")


class TestEnShiftCipherEdgeCases(unittest.TestCase):
    """Additional edge cases and special scenarios"""
    
    def test_alphabet_wrapping_forward(self):
        """Test wrapping from Z to A"""
        result = En_Shift_Cipher("XYZ", 3)
        
        # X(23)+3=26mod26=0=A, Y(24)+3=27mod26=1=B, Z(25)+3=28mod26=2=C
        self.assertEqual(result["Encrypted"], "ABC", "XYZ+3 should wrap to ABC")
    
    def test_alphabet_wrapping_backward(self):
        """Test wrapping from A to Z"""
        result = En_Shift_Cipher("ABC", -3)
        
        # A(0)-3=-3mod26=23=X, B(1)-3=-2mod26=24=Y, C(2)-3=-1mod26=25=Z
        self.assertEqual(result["Encrypted"], "XYZ", "ABC-3 should wrap to XYZ")
    
    def test_all_alphabet_letters(self):
        """Test with complete alphabet"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = En_Shift_Cipher(alphabet, 1)
        
        expected = "BCDEFGHIJKLMNOPQRSTUVWXYZA"
        self.assertEqual(result["Encrypted"], expected, 
                        "Complete alphabet shifted by 1")
    
    def test_rot13_self_inverse(self):
        """Test that ROT13 is self-inverse (applying twice gives original)"""
        original = "HELLO"
        
        # First encryption
        result1 = En_Shift_Cipher(original, 13)
        encrypted = result1["Encrypted"]
        
        # Second encryption (should decrypt)
        result2 = En_Shift_Cipher(encrypted, 13)
        decrypted = result2["Encrypted"]
        
        self.assertEqual(decrypted, original, 
                        "ROT13 applied twice should give original")
    
    def test_sentence_encryption(self):
        """Test encryption of a complete sentence"""
        sentence = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        result = En_Shift_Cipher(sentence, 7)
        
        # Verify it's a valid result
        self.assertIsInstance(result["Encrypted"], str)
        self.assertEqual(len(result["Encrypted"]), len(sentence), 
                        "Length should be preserved")
        
        # Verify spaces are preserved
        encrypted = result["Encrypted"]
        self.assertEqual(encrypted[3], ' ', "Space at position 3 should be preserved")
        self.assertEqual(encrypted[9], ' ', "Space at position 9 should be preserved")
    
    def test_mixed_content(self):
        """Test with mixed letters, numbers, and symbols"""
        mixed = "Test123!@#ABC"
        result = En_Shift_Cipher(mixed, 5)
        
        encrypted = result["Encrypted"]
        
        # Numbers should remain: 123
        self.assertIn("123", encrypted)
        # Symbols should remain: !@#
        self.assertIn("!@#", encrypted)
        # Letters should be shifted
        self.assertNotEqual(encrypted, mixed.upper())
    
    def test_shift_equivalence(self):
        """Test that shift+26 gives same result as shift"""
        text = "EXAMPLE"
        shift1 = 7
        shift2 = 7 + 26  # 33
        
        result1 = En_Shift_Cipher(text, shift1)
        result2 = En_Shift_Cipher(text, shift2)
        
        self.assertEqual(result1["Encrypted"], result2["Encrypted"], 
                        "Shift and shift+26 should give same result")
    
    def test_large_negative_shift(self):
        """Test with large negative shift"""
        result = En_Shift_Cipher("ABC", -30)
        
        # -30 mod 26 = -4 mod 26 = 22
        # A(0)+22=22=W, B(1)+22=23=X, C(2)+22=24=Y
        self.assertEqual(result["Encrypted"], "WXY", "ABC with shift -30 should be WXY")
    
    def test_return_structure(self):
        """Test that return value has correct structure"""
        result = En_Shift_Cipher("TEST", 5)
        
        self.assertIsInstance(result, dict, "Return should be a dictionary")
        self.assertIn("Encrypted", result, "Should contain 'Encrypted' key")
        self.assertIn("Key", result, "Should contain 'Key' key")
        self.assertEqual(len(result), 2, "Should have exactly 2 keys")
        self.assertIsInstance(result["Encrypted"], str, "Encrypted should be string")
        self.assertIsInstance(result["Key"], int, "Key should be integer")


class TestDeShiftCipher(unittest.TestCase):
    """
    Black Box Testing for Shift Cipher Decryption
    
    Test Plan:
    - PE1: Shift = 0 (no decryption)
    - PE2: Standard decryption
    - PE3: Shift = 13 (ROT13)
    - PE4: Large shifts
    - PE5: Negative shift
    - PE6: Empty string
    - PE7: Case handling (lowercase, mixed)
    - PE8: Non-alphabetic characters
    - PE9: Encrypt-Decrypt round-trip
    - Boundary: Alphabet wrapping, long strings
    """
    
    # TC01: PE1 - Shift = 0 (no decryption)
    def test_tc01_shift_zero(self):
        """Test case TC01: Shift by 0 should return unchanged string"""
        result = De_Shift_Cipher("KHOOR", 0)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Decrypted", result)
        self.assertEqual(result["Decrypted"], "KHOOR", "Shift 0 should not change string")
    
    # TC02: PE2 - Standard decryption (reverse of encryption)
    def test_tc02_standard_decryption(self):
        """Test case TC02: Decrypt KHOOR with shift 3 should give HELLO"""
        result = De_Shift_Cipher("KHOOR", 3)
        
        self.assertEqual(result["Decrypted"], "HELLO", "KHOOR decrypted by 3 should be HELLO")
    
    # TC03: PE3 - ROT13 (self-inverse)
    def test_tc03_rot13(self):
        """Test case TC03: ROT13 decryption"""
        result = De_Shift_Cipher("URYYB", 13)
        
        self.assertEqual(result["Decrypted"], "HELLO", "URYYB with ROT13 should be HELLO")
    
    # TC04: PE4 - Shift = 25
    def test_tc04_shift_twenty_five(self):
        """Test case TC04: Decrypt with shift 25"""
        result = De_Shift_Cipher("GDKKN", 25)
        
        # G(6) - 25 = -19 mod 26 = 7 = H
        # D(3) - 25 = -22 mod 26 = 4 = E
        self.assertEqual(result["Decrypted"], "HELLO", "GDKKN decrypted by 25 should be HELLO")
    
    # TC05: PE5 - Shift = 26 (full rotation)
    def test_tc05_shift_twenty_six(self):
        """Test case TC05: Shift 26 should complete full rotation"""
        result = De_Shift_Cipher("KHOOR", 26)
        
        self.assertEqual(result["Decrypted"], "KHOOR", "Shift 26 should be same as shift 0")
    
    # TC06: PE6 - Negative shift
    def test_tc06_negative_shift(self):
        """Test case TC06: Negative shift in decryption"""
        result = De_Shift_Cipher("KHOOR", -3)
        
        # K(10) - (-3) = 13 = N
        # H(7) - (-3) = 10 = K
        self.assertEqual(result["Decrypted"], "NKRRU", "KHOOR decrypted by -3 should be NKRRU")
    
    # TC07: PE7 - Large shift > 26
    def test_tc07_large_shift(self):
        """Test case TC07: Shift > 26 should wrap around"""
        result = De_Shift_Cipher("DEF", 29)
        
        # 29 mod 26 = 3, so D-3=A, E-3=B, F-3=C
        self.assertEqual(result["Decrypted"], "ABC", "DEF decrypted by 29 should be ABC")
    
    # TC08: PE8 - Empty string
    def test_tc08_empty_string(self):
        """Test case TC08: Empty string should return empty"""
        result = De_Shift_Cipher("", 5)
        
        self.assertEqual(result["Decrypted"], "", "Empty string should return empty")
    
    # TC09: PE9 - Lowercase letters
    def test_tc09_lowercase_input(self):
        """Test case TC09: Lowercase letters should be converted to uppercase"""
        result = De_Shift_Cipher("khoor", 3)
        
        self.assertEqual(result["Decrypted"], "HELLO", "Lowercase should be converted and decrypted")
    
    # TC10: PE10 - Mixed case
    def test_tc10_mixed_case(self):
        """Test case TC10: Mixed case should all become uppercase"""
        result = De_Shift_Cipher("KhOoR", 3)
        
        self.assertEqual(result["Decrypted"], "HELLO", "Mixed case should normalize to uppercase")
    
    # TC11: PE11 - String with numbers
    def test_tc11_string_with_numbers(self):
        """Test case TC11: Numbers should remain unchanged"""
        result = De_Shift_Cipher("KHOOR123", 3)
        
        self.assertEqual(result["Decrypted"], "HELLO123", "Numbers should not be decrypted")
    
    # TC12: PE12 - String with special characters
    def test_tc12_special_characters(self):
        """Test case TC12: Special characters should remain unchanged"""
        result = De_Shift_Cipher("KHOOR ZRUOG!", 3)
        
        self.assertEqual(result["Decrypted"], "HELLO WORLD!", 
                        "Spaces and punctuation should remain unchanged")
    
    # TC13: PE13 - Encrypt-Decrypt round-trip
    def test_tc13_encrypt_decrypt_roundtrip(self):
        """Test case TC13: Encrypt then decrypt should give original"""
        original = "HELLO WORLD"
        shift = 7
        
        # Encrypt
        encrypted_result = En_Shift_Cipher(original, shift)
        encrypted = encrypted_result["Encrypted"]
        
        # Decrypt
        decrypted_result = De_Shift_Cipher(encrypted, shift)
        decrypted = decrypted_result["Decrypted"]
        
        self.assertEqual(decrypted, original, 
                        "Encrypt then decrypt should give original text")
    
    # TC14: Boundary - Very long string
    def test_tc14_long_string(self):
        """Test case TC14: Very long string (1000 characters)"""
        long_string = "N" * 1000
        result = De_Shift_Cipher(long_string, 13)
        
        expected = "A" * 1000  # N shifted back by 13 is A
        self.assertEqual(result["Decrypted"], expected, "Long string should be processed correctly")
        self.assertEqual(len(result["Decrypted"]), 1000, "Output length should match input")
    
    # TC15: PE14 - Alphabet wrapping backward
    def test_tc15_alphabet_wrapping(self):
        """Test case TC15: Test wrapping from beginning to end of alphabet"""
        result = De_Shift_Cipher("ABC", 3)
        
        # A(0)-3=-3mod26=23=X, B(1)-3=-2mod26=24=Y, C(2)-3=-1mod26=25=Z
        self.assertEqual(result["Decrypted"], "XYZ", "ABC-3 should wrap to XYZ")


class TestDeShiftCipherEdgeCases(unittest.TestCase):
    """Additional edge cases for decryption"""
    
    def test_alphabet_full_decrypt(self):
        """Test decrypting complete alphabet"""
        encrypted = "BCDEFGHIJKLMNOPQRSTUVWXYZA"
        result = De_Shift_Cipher(encrypted, 1)
        
        expected = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.assertEqual(result["Decrypted"], expected, 
                        "Complete alphabet shifted back by 1")
    
    def test_rot13_twice_gives_original(self):
        """Test that ROT13 applied twice gives original (encryption property)"""
        original = "HELLO"
        
        # First ROT13 (encrypt)
        result1 = En_Shift_Cipher(original, 13)
        encrypted = result1["Encrypted"]
        
        # Second ROT13 (decrypt)
        result2 = De_Shift_Cipher(encrypted, 13)
        decrypted = result2["Decrypted"]
        
        self.assertEqual(decrypted, original, "ROT13 twice should give original")
    
    def test_decrypt_with_various_shifts(self):
        """Test decryption with multiple shift values"""
        encrypted = "KHOOR"
        
        test_cases = [
            (3, "HELLO"),
            (0, "KHOOR"),
            (26, "KHOOR"),
            (-23, "HELLO"),  # -23 mod 26 = 3
        ]
        
        for shift, expected in test_cases:
            with self.subTest(shift=shift):
                result = De_Shift_Cipher(encrypted, shift)
                self.assertEqual(result["Decrypted"], expected)
    
    def test_encrypt_decrypt_symmetry(self):
        """Test that encryption and decryption are symmetric operations"""
        test_strings = ["HELLO", "WORLD", "TEST", "ABCXYZ"]
        shifts = [1, 3, 7, 13, 25]
        
        for text in test_strings:
            for shift in shifts:
                with self.subTest(text=text, shift=shift):
                    # Encrypt
                    enc_result = En_Shift_Cipher(text, shift)
                    encrypted = enc_result["Encrypted"]
                    
                    # Decrypt
                    dec_result = De_Shift_Cipher(encrypted, shift)
                    decrypted = dec_result["Decrypted"]
                    
                    self.assertEqual(decrypted, text, 
                                   f"Symmetry failed for '{text}' with shift {shift}")
    
    def test_sentence_decryption(self):
        """Test decryption of a complete sentence"""
        # First encrypt a sentence
        sentence = "THE QUICK BROWN FOX"
        enc_result = En_Shift_Cipher(sentence, 5)
        encrypted = enc_result["Encrypted"]
        
        # Then decrypt
        dec_result = De_Shift_Cipher(encrypted, 5)
        decrypted = dec_result["Decrypted"]
        
        self.assertEqual(decrypted, sentence, "Sentence should decrypt correctly")
    
    def test_return_structure(self):
        """Test that return value has correct structure"""
        result = De_Shift_Cipher("TEST", 5)
        
        self.assertIsInstance(result, dict, "Return should be a dictionary")
        self.assertIn("Decrypted", result, "Should contain 'Decrypted' key")
        self.assertEqual(len(result), 1, "Should have exactly 1 key")
        self.assertIsInstance(result["Decrypted"], str, "Decrypted should be string")
    
    def test_mixed_content_decryption(self):
        """Test decryption with mixed letters, numbers, and symbols"""
        # Encrypt first
        original = "Test123!@#ABC"
        enc_result = En_Shift_Cipher(original, 5)
        encrypted = enc_result["Encrypted"]
        
        # Decrypt
        dec_result = De_Shift_Cipher(encrypted, 5)
        decrypted = dec_result["Decrypted"]
        
        # Should match original (uppercase)
        self.assertEqual(decrypted, original.upper())
        # Numbers and symbols should be preserved
        self.assertIn("123", decrypted)
        self.assertIn("!@#", decrypted)


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestEnShiftCipher))
    suite.addTest(unittest.makeSuite(TestEnShiftCipherEdgeCases))
    suite.addTest(unittest.makeSuite(TestDeShiftCipher))
    suite.addTest(unittest.makeSuite(TestDeShiftCipherEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
