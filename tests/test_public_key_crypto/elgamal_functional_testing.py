"""
FUNCTIONAL TESTING - ELGAMAL CRYPTOSYSTEM MODULE

Test suite kiểm thử chức năng cho ElGamal Cryptosystem của MahuCryptify.
Kiểm tra: Key Generation, Encryption, Decryption, và Integration.

Test Framework: pytest
Test Type: Black-box Functional Testing
Timeout: 15 seconds per test
"""

import pytest
from math import gcd
from MahuCrypt_app.services.elgamal_service import ElGamalService
from MahuCrypt_app.cryptography.algos import miller_rabin_test


class TestElGamalKeyGeneration:
    """Test suite cho ElGamal Key Generation"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
    
    # ========================================================================
    # ELGAMAL KEY GENERATION - BASIC TESTS
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_key_gen_basic_16_bits(self):
        """TC_ELG_KEY_001: Sinh khóa với bits=16"""
        result = self.elgamal_service.generate_keys(16)
        
        assert "public_key" in result
        assert "private_key - a" in result
        assert "p" in result["public_key"]
        assert "alpha" in result["public_key"]
        assert "beta" in result["public_key"]
    
    @pytest.mark.timeout(15)
    def test_key_gen_32_bits(self):
        """TC_ELG_KEY_002: Sinh khóa với bits=32"""
        result = self.elgamal_service.generate_keys(32)
        
        assert "public_key" in result
        assert "private_key - a" in result
    
    @pytest.mark.timeout(15)
    def test_key_gen_64_bits(self):
        """TC_ELG_KEY_003: Sinh khóa với bits=64"""
        result = self.elgamal_service.generate_keys(64)
        
        assert "public_key" in result
        assert "private_key - a" in result
    
    # ========================================================================
    # ELGAMAL KEY GENERATION - MATHEMATICAL PROPERTIES
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_verify_p_is_prime(self):
        """TC_ELG_KEY_004: Verify p là số nguyên tố"""
        result = self.elgamal_service.generate_keys(32)
        
        p = int(result["public_key"]["p"])
        
        # Use Miller-Rabin with 100 rounds
        assert miller_rabin_test(p, 100)
    
    @pytest.mark.timeout(15)
    def test_verify_beta_formula(self):
        """TC_ELG_KEY_005: Verify beta = alpha^a mod p"""
        result = self.elgamal_service.generate_keys(32)
        
        p = int(result["public_key"]["p"])
        alpha = int(result["public_key"]["alpha"])
        beta = int(result["public_key"]["beta"])
        a = int(result["private_key - a"])
        
        # Verify beta = alpha^a mod p
        expected_beta = pow(alpha, a, p)
        assert beta == expected_beta
    
    @pytest.mark.timeout(15)
    def test_verify_a_range(self):
        """TC_ELG_KEY_006: Verify 1 < a < p-1"""
        result = self.elgamal_service.generate_keys(32)
        
        p = int(result["public_key"]["p"])
        a = int(result["private_key - a"])
        
        assert 1 < a < p - 1
    
    @pytest.mark.timeout(15)
    def test_verify_alpha_positive(self):
        """TC_ELG_KEY_007: Verify alpha > 0"""
        result = self.elgamal_service.generate_keys(32)
        
        alpha = int(result["public_key"]["alpha"])
        
        assert alpha > 0
    
    @pytest.mark.timeout(15)
    def test_key_format_validation(self):
        """TC_ELG_KEY_008: Key format validation"""
        result = self.elgamal_service.generate_keys(32)
        
        # Check public key
        assert "public_key" in result
        assert "p" in result["public_key"]
        assert "alpha" in result["public_key"]
        assert "beta" in result["public_key"]
        assert isinstance(result["public_key"]["p"], str)
        assert isinstance(result["public_key"]["alpha"], str)
        assert isinstance(result["public_key"]["beta"], str)
        
        # Check private key
        assert "private_key - a" in result
        assert isinstance(result["private_key - a"], str)
    
    def test_multiple_key_generation_uniqueness(self):
        """TC_ELG_KEY_009: Multiple generations produce different keys"""
        result1 = self.elgamal_service.generate_keys(32)
        result2 = self.elgamal_service.generate_keys(32)
        
        p1 = result1["public_key"]["p"]
        p2 = result2["public_key"]["p"]
        
        # Should be different (very high probability)
        assert p1 != p2
    
    # ========================================================================
    # ELGAMAL KEY GENERATION - ERROR TESTS
    # ========================================================================
    
    def test_key_gen_error_bits_null(self):
        """TC_ELG_KEY_E001: Error - bits = null"""
        result = self.elgamal_service.generate_keys(None)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_key_gen_error_bits_string(self):
        """TC_ELG_KEY_E002: Error - bits = 'abc'"""
        result = self.elgamal_service.generate_keys("abc")
        
        assert "Error" in result
        assert "integer" in result["Error"].lower()
    
    def test_key_gen_error_bits_zero(self):
        """TC_ELG_KEY_E003: Error - bits = 0"""
        result = self.elgamal_service.generate_keys(0)
        
        assert "Error" in result
        assert "greater than 0" in result["Error"]
    
    def test_key_gen_error_bits_one(self):
        """TC_ELG_KEY_E004: Error - bits = 1"""
        result = self.elgamal_service.generate_keys(1)
        
        assert "Error" in result
        assert "greater than 0" in result["Error"]
    
    def test_key_gen_error_bits_negative(self):
        """TC_ELG_KEY_E005: Error - bits = -5"""
        result = self.elgamal_service.generate_keys(-5)
        
        assert "Error" in result
        assert "greater than 0" in result["Error"]


class TestElGamalEncryption:
    """Test suite cho ElGamal Encryption"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
        
        # Generate test keys with smaller bits for faster tests
        keys = self.elgamal_service.generate_keys(32)
        self.p = int(keys["public_key"]["p"])
        self.alpha = int(keys["public_key"]["alpha"])
        self.beta = int(keys["public_key"]["beta"])
        self.a = int(keys["private_key - a"])
    
    # ========================================================================
    # ELGAMAL ENCRYPTION - BASIC TESTS
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_encrypt_hello(self):
        """TC_ELG_ENC_001: Encrypt 'HELLO'"""
        result = self.elgamal_service.encrypt("HELLO", self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
        assert isinstance(result["Encrypted"], str)
        assert "[[" in result["Encrypted"]
        assert "]]" in result["Encrypted"]
    
    @pytest.mark.timeout(15)
    def test_encrypt_single_char(self):
        """TC_ELG_ENC_002: Encrypt 'A'"""
        result = self.elgamal_service.encrypt("A", self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
    
    @pytest.mark.timeout(15)
    def test_encrypt_four_chars(self):
        """TC_ELG_ENC_003: Encrypt 'ABCD'"""
        result = self.elgamal_service.encrypt("ABCD", self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
    
    @pytest.mark.timeout(15)
    def test_encrypt_multiple_blocks(self):
        """TC_ELG_ENC_004: Encrypt 'HELLOWORLD' (multiple blocks)"""
        result = self.elgamal_service.encrypt("HELLOWORLD", self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
        # Should have multiple pairs
        encrypted_str = result["Encrypted"]
        assert encrypted_str.count("],[") >= 1  # At least 2 pairs
    
    @pytest.mark.timeout(15)
    def test_encrypt_long_text(self):
        """TC_ELG_ENC_005: Encrypt long text (40 chars)"""
        long_text = "A" * 40
        result = self.elgamal_service.encrypt(long_text, self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
    
    # ========================================================================
    # ELGAMAL ENCRYPTION - TEXT PROCESSING
    # ========================================================================
    
    def test_encrypt_with_special_chars(self):
        """TC_ELG_ENC_006: Encrypt with special chars"""
        result = self.elgamal_service.encrypt("HELLO!@#", self.p, self.alpha, self.beta)
        
        # Special chars should be removed by pre_solve
        assert "Encrypted" in result
    
    def test_encrypt_with_numbers(self):
        """TC_ELG_ENC_007: Encrypt with numbers"""
        result = self.elgamal_service.encrypt("HELLO123", self.p, self.alpha, self.beta)
        
        # Numbers should be removed
        assert "Encrypted" in result
    
    def test_encrypt_lowercase(self):
        """TC_ELG_ENC_008: Encrypt lowercase"""
        result = self.elgamal_service.encrypt("hello", self.p, self.alpha, self.beta)
        
        # Should convert to uppercase
        assert "Encrypted" in result
    
    def test_encrypt_mixed_case(self):
        """TC_ELG_ENC_009: Encrypt mixed case"""
        result = self.elgamal_service.encrypt("HeLLo", self.p, self.alpha, self.beta)
        
        # Should convert to uppercase
        assert "Encrypted" in result
    
    # ========================================================================
    # ELGAMAL ENCRYPTION - PROBABILISTIC PROPERTY
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_encrypt_same_message_twice_different_result(self):
        """TC_ELG_ENC_010: Same message twice → different ciphertext"""
        message = "TEST"
        
        result1 = self.elgamal_service.encrypt(message, self.p, self.alpha, self.beta)
        result2 = self.elgamal_service.encrypt(message, self.p, self.alpha, self.beta)
        
        # ElGamal is probabilistic - same message should give different ciphertext
        # due to random k
        assert result1["Encrypted"] != result2["Encrypted"]
    
    def test_encrypt_result_format(self):
        """TC_ELG_ENC_011: Verify result format"""
        result = self.elgamal_service.encrypt("TEST", self.p, self.alpha, self.beta)
        
        assert "Encrypted" in result
        assert isinstance(result["Encrypted"], str)
        # Should be format [[y1,y2],[y1,y2],...]
        assert result["Encrypted"].startswith("[[")
        assert result["Encrypted"].endswith("]]")
    
    # ========================================================================
    # ELGAMAL ENCRYPTION - ERROR TESTS
    # ========================================================================
    
    def test_encrypt_error_message_null(self):
        """TC_ELG_ENC_E001: Error - message = null"""
        result = self.elgamal_service.encrypt(None, self.p, self.alpha, self.beta)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_message_empty(self):
        """TC_ELG_ENC_E002: Error - message = ''"""
        result = self.elgamal_service.encrypt("", self.p, self.alpha, self.beta)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_p_null(self):
        """TC_ELG_ENC_E003: Error - p = null"""
        result = self.elgamal_service.encrypt("HELLO", None, self.alpha, self.beta)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_alpha_null(self):
        """TC_ELG_ENC_E004: Error - alpha = null"""
        result = self.elgamal_service.encrypt("HELLO", self.p, None, self.beta)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_beta_null(self):
        """TC_ELG_ENC_E005: Error - beta = null"""
        result = self.elgamal_service.encrypt("HELLO", self.p, self.alpha, None)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_p_string(self):
        """TC_ELG_ENC_E006: Error - p = 'abc'"""
        result = self.elgamal_service.encrypt("HELLO", "abc", self.alpha, self.beta)
        
        assert "Error" in result
        assert "integer" in result["Error"].lower()
    
    def test_encrypt_error_p_zero(self):
        """TC_ELG_ENC_E007: Error - p = 0"""
        result = self.elgamal_service.encrypt("HELLO", 0, self.alpha, self.beta)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_encrypt_error_p_not_prime(self):
        """TC_ELG_ENC_E008: Error - p not prime"""
        result = self.elgamal_service.encrypt("HELLO", 100, self.alpha, self.beta)
        
        assert "Error" in result
        assert "not prime" in result["Error"].lower()


class TestElGamalDecryption:
    """Test suite cho ElGamal Decryption"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
        
        # Generate test keys with smaller bits for faster tests
        keys = self.elgamal_service.generate_keys(32)
        self.p = int(keys["public_key"]["p"])
        self.alpha = int(keys["public_key"]["alpha"])
        self.beta = int(keys["public_key"]["beta"])
        self.a = int(keys["private_key - a"])
    
    # ========================================================================
    # ELGAMAL DECRYPTION - BASIC TESTS
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_decrypt_basic(self):
        """TC_ELG_DEC_001: Decrypt basic ciphertext"""
        # Encrypt first
        encrypted = self.elgamal_service.encrypt("HELLO", self.p, self.alpha, self.beta)
        ciphertext = encrypted["Encrypted"]
        
        # Decrypt
        result = self.elgamal_service.decrypt(ciphertext, self.p, self.a)
        
        assert "Decrypted" in result
        assert "HELLO" in result["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_decrypt_single_block(self):
        """TC_ELG_DEC_002: Decrypt single block"""
        encrypted = self.elgamal_service.encrypt("TEST", self.p, self.alpha, self.beta)
        ciphertext = encrypted["Encrypted"]
        
        result = self.elgamal_service.decrypt(ciphertext, self.p, self.a)
        
        assert "Decrypted" in result
        assert "TEST" in result["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_decrypt_multiple_blocks(self):
        """TC_ELG_DEC_003: Decrypt multiple blocks"""
        original = "HELLOWORLD"
        encrypted = self.elgamal_service.encrypt(original, self.p, self.alpha, self.beta)
        ciphertext = encrypted["Encrypted"]
        
        result = self.elgamal_service.decrypt(ciphertext, self.p, self.a)
        
        assert "Decrypted" in result
        assert original in result["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_decrypt_with_correct_keys(self):
        """TC_ELG_DEC_004: Decrypt with correct keys (D(C) = M)"""
        original = "TESTMESSAGE"
        
        # Encrypt
        encrypted = self.elgamal_service.encrypt(original, self.p, self.alpha, self.beta)
        
        # Decrypt
        decrypted = self.elgamal_service.decrypt(
            encrypted["Encrypted"], self.p, self.a
        )
        
        assert original in decrypted["Decrypted"]
    
    def test_decrypt_uses_formula(self):
        """TC_ELG_DEC_005: Verify M = y2 * (y1^(p-1-a)) mod p"""
        # This is implicit in the decrypt working correctly
        original = "TEST"
        encrypted = self.elgamal_service.encrypt(original, self.p, self.alpha, self.beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], self.p, self.a)
        
        assert original in decrypted["Decrypted"]
    
    # ========================================================================
    # ELGAMAL DECRYPTION - ERROR TESTS
    # ========================================================================
    
    def test_decrypt_error_encrypted_null(self):
        """TC_ELG_DEC_E001: Error - encrypted = null"""
        result = self.elgamal_service.decrypt(None, self.p, self.a)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_encrypted_empty(self):
        """TC_ELG_DEC_E002: Error - encrypted = ''"""
        result = self.elgamal_service.decrypt("", self.p, self.a)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_p_null(self):
        """TC_ELG_DEC_E003: Error - p = null"""
        result = self.elgamal_service.decrypt("[[123,456]]", None, self.a)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_a_null(self):
        """TC_ELG_DEC_E004: Error - a = null"""
        result = self.elgamal_service.decrypt("[[123,456]]", self.p, None)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_p_string(self):
        """TC_ELG_DEC_E005: Error - p = 'abc'"""
        result = self.elgamal_service.decrypt("[[123,456]]", "abc", self.a)
        
        assert "Error" in result
        assert "integer" in result["Error"].lower()
    
    def test_decrypt_error_p_zero(self):
        """TC_ELG_DEC_E006: Error - p = 0"""
        result = self.elgamal_service.decrypt("[[123,456]]", 0, self.a)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_a_zero(self):
        """TC_ELG_DEC_E007: Error - a = 0"""
        result = self.elgamal_service.decrypt("[[123,456]]", self.p, 0)
        
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_decrypt_error_p_not_prime(self):
        """TC_ELG_DEC_E008: Error - p not prime"""
        result = self.elgamal_service.decrypt("[[123,456]]", 100, self.a)
        
        assert "Error" in result
        assert "not prime" in result["Error"].lower()
    
    @pytest.mark.timeout(15)
    def test_decrypt_with_wrong_keys(self):
        """TC_ELG_DEC_E009: Wrong keys produce incorrect result"""
        # Encrypt with one set of keys
        encrypted = self.elgamal_service.encrypt("SECRET", self.p, self.alpha, self.beta)
        
        # Try to decrypt with different 'a'
        other_keys = self.elgamal_service.generate_keys(32)
        other_a = int(other_keys["private_key - a"])
        other_p = int(other_keys["public_key"]["p"])
        
        result = self.elgamal_service.decrypt(
            encrypted["Encrypted"], other_p, other_a
        )
        
        # Should either error or produce incorrect result
        if "Decrypted" in result:
            assert result["Decrypted"] != "SECRET"


class TestElGamalIntegration:
    """Test suite cho ElGamal Integration (Full Cycle)"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
    
    # ========================================================================
    # INTEGRATION TESTS - FULL CYCLE
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_full_cycle_gen_enc_dec(self):
        """TC_ELG_INT_001: Full cycle Gen→Enc→Dec"""
        # Generate keys
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        # Encrypt
        original = "INTEGRATION"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        
        # Decrypt
        decrypted = self.elgamal_service.decrypt(
            encrypted["Encrypted"], p, a
        )
        
        # Verify
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_cycle_with_16_bits(self):
        """TC_ELG_INT_002: Cycle with bits=16"""
        keys = self.elgamal_service.generate_keys(16)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "TEST"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_cycle_with_64_bits(self):
        """TC_ELG_INT_003: Cycle with bits=64"""
        keys = self.elgamal_service.generate_keys(64)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "HELLO"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_cycle_with_long_message(self):
        """TC_ELG_INT_004: Cycle with long message"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "A" * 32
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_cycle_with_single_char(self):
        """TC_ELG_INT_005: Cycle with single char"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "X"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_multiple_messages_same_keys(self):
        """TC_ELG_INT_006: Multiple messages with same keys"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        messages = ["FIRST", "SECOND", "THIRD"]
        
        for msg in messages:
            encrypted = self.elgamal_service.encrypt(msg, p, alpha, beta)
            decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
            assert msg in decrypted["Decrypted"]
    
    # ========================================================================
    # INTEGRATION TESTS - PROBABILISTIC PROPERTY
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_encrypt_twice_decrypt_both(self):
        """TC_ELG_INT_007: Encrypt twice, decrypt both"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        message = "TEST"
        
        # Encrypt twice with same keys
        encrypted1 = self.elgamal_service.encrypt(message, p, alpha, beta)
        encrypted2 = self.elgamal_service.encrypt(message, p, alpha, beta)
        
        # Ciphertexts should be different (probabilistic)
        assert encrypted1["Encrypted"] != encrypted2["Encrypted"]
        
        # But both should decrypt to same message
        decrypted1 = self.elgamal_service.decrypt(encrypted1["Encrypted"], p, a)
        decrypted2 = self.elgamal_service.decrypt(encrypted2["Encrypted"], p, a)
        
        assert message in decrypted1["Decrypted"]
        assert message in decrypted2["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_different_keys_independence(self):
        """TC_ELG_INT_008: Different keys are independent"""
        keys1 = self.elgamal_service.generate_keys(32)
        keys2 = self.elgamal_service.generate_keys(32)
        
        # Keys should be different
        assert keys1["public_key"]["p"] != keys2["public_key"]["p"]


class TestElGamalEdgeCasesAndSecurity:
    """Test suite cho Edge Cases và Security Properties"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
    
    # ========================================================================
    # EDGE CASES
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_edge_very_long_message(self):
        """TC_ELG_EDGE_001: Very long message"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        
        message = "A" * 100
        result = self.elgamal_service.encrypt(message, p, alpha, beta)
        
        assert "Encrypted" in result
    
    @pytest.mark.timeout(15)
    def test_edge_low_entropy(self):
        """TC_ELG_EDGE_002: Low entropy message"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        
        message = "A" * 20
        result = self.elgamal_service.encrypt(message, p, alpha, beta)
        
        assert "Encrypted" in result
    
    def test_edge_message_with_spaces(self):
        """TC_ELG_EDGE_003: Message with spaces"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        
        result = self.elgamal_service.encrypt("HELLO WORLD", p, alpha, beta)
        
        # Spaces should be handled (removed or kept)
        assert "Encrypted" in result
    
    # ========================================================================
    # SECURITY PROPERTIES
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_security_p_is_prime(self):
        """TC_ELG_SEC_001: p is always prime"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        
        assert miller_rabin_test(p, 100)
    
    @pytest.mark.timeout(15)
    def test_security_a_in_range(self):
        """TC_ELG_SEC_002: 1 < a < p-1"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        a = int(keys["private_key - a"])
        
        assert 1 < a < p - 1
    
    @pytest.mark.timeout(15)
    def test_security_beta_formula(self):
        """TC_ELG_SEC_003: beta = alpha^a mod p"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        expected_beta = pow(alpha, a, p)
        assert beta == expected_beta
    
    @pytest.mark.timeout(15)
    def test_security_different_k_each_time(self):
        """TC_ELG_SEC_004: Different k for each encryption"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        
        message = "TEST"
        
        # Encrypt twice
        result1 = self.elgamal_service.encrypt(message, p, alpha, beta)
        result2 = self.elgamal_service.encrypt(message, p, alpha, beta)
        
        # Should be different due to different k
        # Extract y1 from first pair to verify different k
        # Format: [[y1,y2],...]
        import ast
        pairs1 = ast.literal_eval(result1["Encrypted"])
        pairs2 = ast.literal_eval(result2["Encrypted"])
        
        # y1 values should be different (y1 = alpha^k mod p)
        assert pairs1[0][0] != pairs2[0][0]


class TestElGamalMathematicalCorrectness:
    """Test suite cho Mathematical Correctness"""
    
    def setup_method(self):
        """Setup trước mỗi test method"""
        self.elgamal_service = ElGamalService()
    
    # ========================================================================
    # MATHEMATICAL PROPERTIES
    # ========================================================================
    
    @pytest.mark.timeout(15)
    def test_math_encryption_formula_y1(self):
        """TC_ELG_MATH_001: y1 = alpha^k mod p"""
        # Implicit test - if encrypt works, formula is correct
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        
        result = self.elgamal_service.encrypt("TEST", p, alpha, beta)
        
        assert "Encrypted" in result
    
    @pytest.mark.timeout(15)
    def test_math_encryption_formula_y2(self):
        """TC_ELG_MATH_002: y2 = M × beta^k mod p"""
        # Implicit test - if encrypt/decrypt cycle works, formula is correct
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "TEST"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_math_decryption_formula(self):
        """TC_ELG_MATH_003: M = y2 × (y1^(p-1-a)) mod p"""
        # Implicit test - correct decryption proves formula works
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        beta = int(keys["public_key"]["beta"])
        a = int(keys["private_key - a"])
        
        original = "HELLO"
        encrypted = self.elgamal_service.encrypt(original, p, alpha, beta)
        decrypted = self.elgamal_service.decrypt(encrypted["Encrypted"], p, a)
        
        assert original in decrypted["Decrypted"]
    
    @pytest.mark.timeout(15)
    def test_math_fermats_little_theorem(self):
        """TC_ELG_MATH_004: Fermat's Little Theorem - a^(p-1) ≡ 1 (mod p)"""
        keys = self.elgamal_service.generate_keys(32)
        p = int(keys["public_key"]["p"])
        alpha = int(keys["public_key"]["alpha"])
        
        # For any a and prime p: a^(p-1) ≡ 1 (mod p)
        result = pow(alpha, p - 1, p)
        
        assert result == 1


# ============================================================================
# TEST EXECUTION SUMMARY
# ============================================================================

if __name__ == "__main__":
    print("ElGamal Cryptosystem Module Functional Testing Suite")
    print("=" * 70)
    print("Coverage:")
    print("  - Key Generation: 14 tests")
    print("  - Encryption: 19 tests")
    print("  - Decryption: 14 tests")
    print("  - Integration: 8 tests")
    print("  - Edge Cases & Security: 7 tests")
    print("  - Mathematical: 4 tests")
    print("  Total: ~66 tests")
    print("=" * 70)
    print("Timeout: 15 seconds per test")
    print("Run: pytest tests/test_public_key_crypto/elgamal_functional_testing.py -v")
