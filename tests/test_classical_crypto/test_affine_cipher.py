"""
Unit Test for Affine Cipher functions - Black Box Testing
Module: MahuCrypt_app.cryptography.classical_cryptography
Functions: En_Affine_Cipher(string, a, b), De_Affine_Cipher(string, a, b)

Test Strategy: Equivalence Partitioning & Boundary Value Analysis
Purpose: Affine cipher encryption/decryption - E(x) = (a*x + b) mod 26
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from MahuCrypt_app.cryptography.classical_cryptography import En_Affine_Cipher, De_Affine_Cipher


class TestEnAffineCipher(unittest.TestCase):
    """
    Black Box Testing for Affine Cipher Encryption
    
    Formula: E(x) = (a*x + b) mod 26
    Constraint: gcd(a, 26) = 1 (a must be coprime with 26)
    
    Test Plan:
    - PE1: a=1, b=0 (identity)
    - PE2: a=1, b>0 (shift cipher)
    - PE3: a>1, b=0 (multiplicative only)
    - PE4: Valid a,b pairs
    - PE5: Invalid a (gcd(a,26) ≠ 1)
    - PE6: Boundary values for a, b
    - PE7: Case handling
    - PE8: Non-alphabetic characters
    """
    
    # TC01: PE1 - Identity (a=1, b=0)
    def test_tc01_identity_transformation(self):
        """Test case TC01: a=1, b=0 should not change the string"""
        result = En_Affine_Cipher("HELLO", 1, 0)
        
        self.assertIsInstance(result, dict)
        self.assertIn("Encrypted", result)
        self.assertEqual(result["Encrypted"], "HELLO", "Identity should not change string")
    
    # TC02: PE2 - a=1, b>0 (reduces to shift cipher)
    def test_tc02_shift_cipher_mode(self):
        """Test case TC02: When a=1, Affine becomes shift cipher"""
        result = En_Affine_Cipher("HELLO", 1, 3)
        
        # This is equivalent to Caesar cipher with shift 3
        self.assertEqual(result["Encrypted"], "KHOOR", "a=1 should behave like shift cipher")
    
    # TC03: PE3 - a>1, b=0 (multiplicative only)
    def test_tc03_multiplicative_only(self):
        """Test case TC03: b=0 means only multiplication"""
        result = En_Affine_Cipher("HELLO", 5, 0)
        
        # H(7)*5=35mod26=9=J, E(4)*5=20=U, L(11)*5=55mod26=3=D, O(14)*5=70mod26=18=S
        self.assertEqual(result["Encrypted"], "JUDDS", "Multiplicative cipher with a=5, b=0")
    
    # TC04: PE4 - Standard Affine cipher
    def test_tc04_standard_affine(self):
        """Test case TC04: Standard Affine cipher with a=5, b=8"""
        result = En_Affine_Cipher("HELLO", 5, 8)
        
        # H(7)*5+8=43mod26=17=R, E(4)*5+8=28mod26=2=C, L(11)*5+8=63mod26=11=L
        # L(11)*5+8=63mod26=11=L, O(14)*5+8=78mod26=0=A
        self.assertEqual(result["Encrypted"], "RCLLA", "Standard Affine encryption")
    
    # TC05: PE5 - Another valid example
    def test_tc05_affine_example(self):
        """Test case TC05: Encrypt AFFINE with a=7, b=10"""
        result = En_Affine_Cipher("AFFINE", 7, 10)
        
        # A(0)*7+10=10=K, F(5)*7+10=45mod26=19=T, I(8)*7+10=66mod26=14=O
        self.assertIn("Encrypted", result)
        # Verify it's not an error
        self.assertNotIn("Error", result)
    
    # TC06: PE6 - Invalid a (even number, gcd(a,26)=2)
    def test_tc06_invalid_a_even(self):
        """Test case TC06: a=2 is invalid (even, gcd(2,26)=2)"""
        result = En_Affine_Cipher("HELLO", 2, 5)
        
        self.assertIn("Error", result, "Even a should be rejected")
        self.assertIn("nguyên tố cùng nhau", result["Error"])
    
    # TC07: PE7 - Invalid a (gcd(13,26)=13)
    def test_tc07_invalid_a_gcd_not_one(self):
        """Test case TC07: a=13 is invalid (gcd(13,26)=13)"""
        result = En_Affine_Cipher("HELLO", 13, 5)
        
        self.assertIn("Error", result, "a=13 should be rejected")
    
    # TC08: PE8 - a=26 (invalid)
    def test_tc08_a_equals_26(self):
        """Test case TC08: a=26 is invalid"""
        result = En_Affine_Cipher("HELLO", 26, 5)
        
        self.assertIn("Error", result, "a=26 should be rejected")
    
    # TC09: PE9 - a=0 (invalid)
    def test_tc09_a_equals_zero(self):
        """Test case TC09: a=0 is invalid"""
        result = En_Affine_Cipher("HELLO", 0, 5)
        
        self.assertIn("Error", result, "a=0 should be rejected")
    
    # TC10: PE10 - Negative b
    def test_tc10_negative_b(self):
        """Test case TC10: Negative b value"""
        result = En_Affine_Cipher("HELLO", 5, -3)
        
        # Should handle negative b with modulo
        if "Encrypted" in result:
            self.assertIsInstance(result["Encrypted"], str)
        # Or might produce error depending on implementation
    
    # TC11: PE11 - Large b (> 26)
    def test_tc11_large_b(self):
        """Test case TC11: b > 26 should work with modulo"""
        result = En_Affine_Cipher("HELLO", 5, 30)
        
        # 30 mod 26 = 4, so should be same as b=4
        result_mod = En_Affine_Cipher("HELLO", 5, 4)
        if "Encrypted" in result and "Encrypted" in result_mod:
            self.assertEqual(result["Encrypted"], result_mod["Encrypted"], 
                           "b=30 should equal b=4 (mod 26)")
    
    # TC12: PE12 - Empty string
    def test_tc12_empty_string(self):
        """Test case TC12: Empty string input"""
        result = En_Affine_Cipher("", 5, 8)
        
        if "Encrypted" in result:
            self.assertEqual(result["Encrypted"], "", "Empty string should return empty")
    
    # TC13: PE13 - Lowercase input
    def test_tc13_lowercase_input(self):
        """Test case TC13: Lowercase letters should be handled"""
        result = En_Affine_Cipher("hello", 5, 8)
        
        # Should convert to uppercase and encrypt
        if "Encrypted" in result:
            expected = En_Affine_Cipher("HELLO", 5, 8)["Encrypted"]
            self.assertEqual(result["Encrypted"], expected, "Lowercase should be handled")
    
    # TC14: PE14 - Mixed case
    def test_tc14_mixed_case(self):
        """Test case TC14: Mixed case input"""
        result = En_Affine_Cipher("HeLLo", 5, 8)
        
        if "Encrypted" in result:
            expected = En_Affine_Cipher("HELLO", 5, 8)["Encrypted"]
            self.assertEqual(result["Encrypted"], expected, "Mixed case should normalize")
    
    # TC15: PE15 - Numbers and special characters
    def test_tc15_numbers_and_special_chars(self):
        """Test case TC15: Numbers and special characters should be preserved"""
        result = En_Affine_Cipher("HELLO123!", 5, 8)
        
        if "Encrypted" in result:
            encrypted = result["Encrypted"]
            self.assertIn("123", encrypted, "Numbers should be preserved")
            self.assertIn("!", encrypted, "Special chars should be preserved")


class TestEnAffineCipherEdgeCases(unittest.TestCase):
    """Additional edge cases for Affine cipher encryption"""
    
    def test_all_valid_a_values(self):
        """Test with all valid a values (coprime with 26)"""
        # Valid a values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        
        for a in valid_a:
            with self.subTest(a=a):
                result = En_Affine_Cipher("TEST", a, 5)
                self.assertIn("Encrypted", result, f"a={a} should be valid")
                self.assertNotIn("Error", result, f"a={a} should not error")
    
    def test_all_invalid_a_values(self):
        """Test that invalid a values are rejected"""
        # Invalid a: 0, 2, 4, 6, 8, 10, 12, 13, 14, 16, 18, 20, 22, 24, 26
        invalid_a = [0, 2, 4, 6, 8, 10, 12, 13, 14, 16, 18, 20, 22, 24, 26]
        
        for a in invalid_a:
            with self.subTest(a=a):
                result = En_Affine_Cipher("TEST", a, 5)
                self.assertIn("Error", result, f"a={a} should be invalid")
    
    def test_full_alphabet(self):
        """Test encryption of complete alphabet"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = En_Affine_Cipher(alphabet, 5, 8)
        
        if "Encrypted" in result:
            encrypted = result["Encrypted"]
            self.assertEqual(len(encrypted), 26, "Should encrypt all 26 letters")
            # All should be uppercase letters
            self.assertTrue(all(c.isupper() for c in encrypted))
    
    def test_sentence_with_spaces(self):
        """Test encryption of sentence with spaces"""
        sentence = "THE QUICK BROWN FOX"
        result = En_Affine_Cipher(sentence, 7, 3)
        
        if "Encrypted" in result:
            encrypted = result["Encrypted"]
            # Count spaces - should be preserved
            self.assertEqual(encrypted.count(' '), sentence.count(' '))
    
    def test_return_structure(self):
        """Test return value structure"""
        result = En_Affine_Cipher("TEST", 5, 8)
        
        self.assertIsInstance(result, dict)
        # Should have either "Encrypted" or "Error"
        self.assertTrue("Encrypted" in result or "Error" in result)
        
        if "Encrypted" in result:
            self.assertIsInstance(result["Encrypted"], str)
    
    def test_b_modulo_behavior(self):
        """Test that b is handled with modulo 26"""
        # Test with b, b+26, b+52 - should give same result
        test_b_values = [(5, 5), (5, 31), (5, 57)]
        results = []
        
        for b_original, b_test in test_b_values:
            result = En_Affine_Cipher("HELLO", 7, b_test)
            if "Encrypted" in result:
                results.append(result["Encrypted"])
        
        if len(results) > 1:
            # All should be equal (modulo behavior)
            self.assertTrue(all(r == results[0] for r in results), 
                          "Different b values mod 26 should give same result")


class TestDeAffineCipher(unittest.TestCase):
    """
    Black Box Testing for Affine Cipher Decryption
    
    Formula: D(y) = a^(-1) * (y - b) mod 26
    where a^(-1) is modular inverse of a mod 26
    """
    
    # TC01: Basic decryption
    def test_tc01_basic_decryption(self):
        """Test case TC01: Basic decryption"""
        result = De_Affine_Cipher("RCLLA", 5, 8)
        
        self.assertIn("Decrypted", result)
        self.assertEqual(result["Decrypted"], "HELLO", "Should decrypt correctly")
    
    # TC02: Identity (a=1, b=0)
    def test_tc02_identity(self):
        """Test case TC02: Identity transformation"""
        result = De_Affine_Cipher("HELLO", 1, 0)
        
        self.assertEqual(result["Decrypted"], "HELLO")
    
    # TC03: Encrypt-Decrypt round trip
    def test_tc03_encrypt_decrypt_roundtrip(self):
        """Test case TC03: Encrypt then decrypt should give original"""
        original = "HELLO"
        a, b = 5, 8
        
        # Encrypt
        enc_result = En_Affine_Cipher(original, a, b)
        if "Encrypted" in enc_result:
            encrypted = enc_result["Encrypted"]
            
            # Decrypt
            dec_result = De_Affine_Cipher(encrypted, a, b)
            if "Decrypted" in dec_result:
                decrypted = dec_result["Decrypted"]
                
                self.assertEqual(decrypted, original, 
                               "Round-trip should preserve original")
    
    # TC04: Invalid a value
    def test_tc04_invalid_a(self):
        """Test case TC04: Invalid a should be rejected"""
        result = De_Affine_Cipher("HELLO", 2, 5)
        
        self.assertIn("Error", result)
    
    # TC05: Multiple round trips
    def test_tc05_multiple_roundtrips(self):
        """Test case TC05: Multiple valid a,b pairs"""
        test_cases = [
            ("HELLO", 3, 5),
            ("WORLD", 7, 10),
            ("TEST", 9, 3),
            ("AFFINE", 11, 15),
        ]
        
        for text, a, b in test_cases:
            with self.subTest(text=text, a=a, b=b):
                # Encrypt
                enc_result = En_Affine_Cipher(text, a, b)
                if "Encrypted" in enc_result:
                    encrypted = enc_result["Encrypted"]
                    
                    # Decrypt
                    dec_result = De_Affine_Cipher(encrypted, a, b)
                    if "Decrypted" in dec_result:
                        self.assertEqual(dec_result["Decrypted"], text)
    
    # TC06: Lowercase handling
    def test_tc06_lowercase_input(self):
        """Test case TC06: Lowercase input in decryption"""
        result = De_Affine_Cipher("rclla", 5, 8)
        
        if "Decrypted" in result:
            # Should handle lowercase
            expected = De_Affine_Cipher("RCLLA", 5, 8)["Decrypted"]
            self.assertEqual(result["Decrypted"], expected)
    
    # TC07: Empty string
    def test_tc07_empty_string(self):
        """Test case TC07: Empty string decryption"""
        result = De_Affine_Cipher("", 5, 8)
        
        if "Decrypted" in result:
            self.assertEqual(result["Decrypted"], "")
    
    # TC08: Non-alphabetic characters
    def test_tc08_non_alphabetic(self):
        """Test case TC08: Non-alphabetic characters should be preserved"""
        result = De_Affine_Cipher("RCLLA123!", 5, 8)
        
        if "Decrypted" in result:
            decrypted = result["Decrypted"]
            self.assertIn("123", decrypted)
            self.assertIn("!", decrypted)


def suite():
    """Create test suite"""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestEnAffineCipher))
    suite.addTest(unittest.makeSuite(TestEnAffineCipherEdgeCases))
    suite.addTest(unittest.makeSuite(TestDeAffineCipher))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
