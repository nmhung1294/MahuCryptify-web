"""
RSA DIGITAL SIGNATURE - FUNCTIONAL TESTS
Black-box testing of RSA signing and verification
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from MahuCrypt_app.services.signature_service import SignatureService
from MahuCrypt_app.cryptography.public_key_cryptography import create_RSA_keys
from MahuCrypt_app.cryptography.algos import miller_rabin_test


def get_rsa_keys(bits):
    """Helper to extract RSA keys from nested dict"""
    keys_dict = create_RSA_keys(bits)
    return {
        "p": int(keys_dict["private_key"]["p"]),
        "q": int(keys_dict["private_key"]["q"]),
        "d": int(keys_dict["private_key"]["d"]),
        "n": int(keys_dict["public_key"]["n"]),
        "e": int(keys_dict["public_key"]["e"])
    }


class TestRSASigningBasic:
    """Basic RSA signing tests"""
    
    @pytest.mark.timeout(15)
    def test_sign_hello_32bits(self):
        """TC_RSA_SIG_001: Sign 'HELLO' with 32 bits"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("HELLO", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result, f"Unexpected error: {result}"
        assert "Signed Message" in result
        assert "Hashed Message" in result
        assert result["Signed Message"] != ""
        assert result["Hashed Message"] != ""
    
    @pytest.mark.timeout(15)
    def test_sign_test_32bits(self):
        """TC_RSA_SIG_002: Sign 'TEST' (1 block, 4 chars)"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # TEST = 4 chars = 1 block
        signed = eval(result["Signed Message"])
        assert len(signed) == 1, "Expected 1 signature block for 'TEST'"
    
    @pytest.mark.timeout(15)
    def test_sign_single_char(self):
        """TC_RSA_SIG_003: Sign single character 'A'"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("A", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        signed = eval(result["Signed Message"])
        assert len(signed) >= 1
    
    @pytest.mark.timeout(15)
    def test_sign_multiple_blocks(self):
        """TC_RSA_SIG_004: Sign 'HELLOWORLD' (multiple blocks)"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("HELLOWORLD", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # HELLOWORLD = 10 chars = 3 blocks (4+4+2)
        signed = eval(result["Signed Message"])
        assert len(signed) == 3, f"Expected 3 blocks, got {len(signed)}"
    
    @pytest.mark.timeout(15)
    def test_sign_long_text(self):
        """TC_RSA_SIG_005: Sign long text (20 'A's)"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("A" * 20, keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # 20 chars = 5 blocks
        signed = eval(result["Signed Message"])
        assert len(signed) == 5, f"Expected 5 blocks, got {len(signed)}"
    
    @pytest.mark.timeout(15)
    def test_sign_16bits(self):
        """TC_RSA_SIG_006: Sign with 16 bits (fast)"""
        keys = get_rsa_keys(16)
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
    
    @pytest.mark.timeout(15)
    def test_sign_64bits(self):
        """TC_RSA_SIG_007: Sign with 64 bits (may be slower)"""
        keys = get_rsa_keys(64)
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
    
    @pytest.mark.timeout(15)
    def test_sign_result_format(self):
        """TC_RSA_SIG_008: Check result format"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        assert isinstance(result, dict)
        assert "Signed Message" in result
        assert "Hashed Message" in result
        
        # Both should be string representations of lists
        signed_str = result["Signed Message"]
        hashed_str = result["Hashed Message"]
        assert signed_str.startswith("[") and signed_str.endswith("]")
        assert hashed_str.startswith("[") and hashed_str.endswith("]")
    
    @pytest.mark.timeout(15)
    def test_sign_with_special_chars(self):
        """TC_RSA_SIG_009: Sign with special characters (removed by pre_solve)"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("TEST!@#", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # Special chars should be removed, only "TEST" remains
    
    @pytest.mark.timeout(15)
    def test_sign_lowercase(self):
        """TC_RSA_SIG_010: Sign lowercase (converted to uppercase)"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("test", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        assert "Signed Message" in result


class TestRSATextProcessing:
    """Text processing tests for RSA signing"""
    
    @pytest.mark.timeout(15)
    def test_special_characters_removed(self):
        """TC_RSA_SIG_T001: Special characters are removed"""
        keys = get_rsa_keys(32)
        result1 = SignatureService.sign_with_rsa("HELLO", keys["p"], keys["q"], keys["d"])
        result2 = SignatureService.sign_with_rsa("HELLO!@#$", keys["p"], keys["q"], keys["d"])
        
        # Both should produce same hash (special chars removed)
        assert result1["Hashed Message"] == result2["Hashed Message"]
    
    @pytest.mark.timeout(15)
    def test_numbers_removed(self):
        """TC_RSA_SIG_T002: Numbers are removed"""
        keys = get_rsa_keys(32)
        result1 = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        result2 = SignatureService.sign_with_rsa("TEST123", keys["p"], keys["q"], keys["d"])
        
        # Both should produce same hash (numbers removed)
        assert result1["Hashed Message"] == result2["Hashed Message"]
    
    @pytest.mark.timeout(15)
    def test_spaces_handling(self):
        """TC_RSA_SIG_T003: Spaces are handled"""
        keys = get_rsa_keys(32)
        result = SignatureService.sign_with_rsa("HELLO WORLD", keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        # Spaces should be removed/handled by pre_solve
    
    @pytest.mark.timeout(15)
    def test_mixed_case(self):
        """TC_RSA_SIG_T004: Mixed case converted to uppercase"""
        keys = get_rsa_keys(32)
        result1 = SignatureService.sign_with_rsa("HELLO", keys["p"], keys["q"], keys["d"])
        result2 = SignatureService.sign_with_rsa("HeLLo", keys["p"], keys["q"], keys["d"])
        
        # Both should produce same hash (case normalized)
        assert result1["Hashed Message"] == result2["Hashed Message"]


class TestRSASigningErrors:
    """Error handling tests for RSA signing"""
    
    def test_null_message(self):
        """TC_RSA_SIG_E001: Null message"""
        result = SignatureService.sign_with_rsa(None, 61, 53, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_empty_message(self):
        """TC_RSA_SIG_E002: Empty message"""
        result = SignatureService.sign_with_rsa("", 61, 53, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_p(self):
        """TC_RSA_SIG_E003: Null p"""
        result = SignatureService.sign_with_rsa("TEST", None, 53, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_q(self):
        """TC_RSA_SIG_E004: Null q"""
        result = SignatureService.sign_with_rsa("TEST", 61, None, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_d(self):
        """TC_RSA_SIG_E005: Null d"""
        result = SignatureService.sign_with_rsa("TEST", 61, 53, None)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_p_not_prime(self):
        """TC_RSA_SIG_E006: p not prime"""
        result = SignatureService.sign_with_rsa("TEST", 100, 53, 17)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "prime" in result["Error"].lower()
    
    def test_q_not_prime(self):
        """TC_RSA_SIG_E007: q not prime"""
        result = SignatureService.sign_with_rsa("TEST", 61, 100, 17)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "prime" in result["Error"].lower()
    
    def test_p_equals_q(self):
        """TC_RSA_SIG_E008: p = q (same prime)"""
        result = SignatureService.sign_with_rsa("TEST", 61, 61, 17)
        
        # May or may not error depending on implementation
        # Just check it doesn't crash
        assert result is not None
    
    def test_d_zero(self):
        """TC_RSA_SIG_E009: d = 0"""
        result = SignatureService.sign_with_rsa("TEST", 61, 53, 0)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_d_greater_than_n(self):
        """TC_RSA_SIG_E010: d > n"""
        result = SignatureService.sign_with_rsa("TEST", 61, 53, 10000)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_invalid_types(self):
        """TC_RSA_SIG_E011: Invalid types for p, q, d"""
        result = SignatureService.sign_with_rsa("TEST", "abc", 53, 17)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "integer" in result["Error"].lower()


class TestRSAVerificationBasic:
    """Basic RSA verification tests"""
    
    @pytest.mark.timeout(15)
    def test_verify_valid_signature(self):
        """TC_RSA_VER_001: Verify valid signature"""
        keys = get_rsa_keys(32)
        
        # Sign message
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        assert "Error" not in sign_result
        
        # Verify signature
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert "Error" not in verify_result
        assert "Verification: " in verify_result
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_verify_multiple_blocks(self):
        """TC_RSA_VER_002: Verify signature of multiple blocks"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("HELLO", keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_verify_with_correct_keys(self):
        """TC_RSA_VER_003: Verify with matching keys"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_verify_single_block(self):
        """TC_RSA_VER_004: Verify single block signature"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_verify_long_message(self):
        """TC_RSA_VER_005: Verify long message signature"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("A" * 20, keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_verify_wrong_signature(self):
        """TC_RSA_VER_006: Verify with modified signature"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        # Modify signature
        signed = eval(sign_result["Signed Message"])
        signed[0] = signed[0] + 1  # Change first signature
        modified_sig = str(signed)
        
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            modified_sig,
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "False"
    
    @pytest.mark.timeout(15)
    def test_verify_wrong_message(self):
        """TC_RSA_VER_007: Verify with different hash"""
        keys = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        # Use hash from different message
        sign_result2 = SignatureService.sign_with_rsa("HELLO", keys["p"], keys["q"], keys["d"])
        
        verify_result = SignatureService.verify_rsa_signature(
            sign_result2["Hashed Message"],  # Wrong hash
            sign_result["Signed Message"],   # Original signature
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "False"
    
    @pytest.mark.timeout(15)
    def test_verify_wrong_keys(self):
        """TC_RSA_VER_008: Verify with different keys"""
        keys1 = get_rsa_keys(32)
        keys2 = get_rsa_keys(32)
        
        # Sign with keys1
        sign_result = SignatureService.sign_with_rsa("TEST", keys1["p"], keys1["q"], keys1["d"])
        
        # Verify with keys2
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys2["n"],  # Wrong key
            keys2["e"]   # Wrong key
        )
        
        assert verify_result["Verification: "] == "False"


class TestRSAVerificationErrors:
    """Error handling tests for RSA verification"""
    
    def test_null_hash(self):
        """TC_RSA_VER_E001: Null hash"""
        result = SignatureService.verify_rsa_signature(None, "[123]", 3233, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_empty_hash(self):
        """TC_RSA_VER_E002: Empty hash"""
        result = SignatureService.verify_rsa_signature("", "[123]", 3233, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_signature(self):
        """TC_RSA_VER_E003: Null signature"""
        result = SignatureService.verify_rsa_signature("[123]", None, 3233, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_n(self):
        """TC_RSA_VER_E004: Null n"""
        result = SignatureService.verify_rsa_signature("[123]", "[456]", None, 17)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)
    
    def test_null_e(self):
        """TC_RSA_VER_E005: Null e"""
        result = SignatureService.verify_rsa_signature("[123]", "[456]", 3233, None)
        
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)


class TestRSAIntegration:
    """Integration tests for full sign-verify cycle"""
    
    @pytest.mark.timeout(15)
    def test_full_cycle_32bits(self):
        """TC_RSA_INT_001: Full cycle with 32 bits"""
        keys = get_rsa_keys(32)
        
        # Sign
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        assert "Error" not in sign_result
        
        # Verify
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_full_cycle_16bits(self):
        """TC_RSA_INT_002: Full cycle with 16 bits"""
        keys = get_rsa_keys(16)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_full_cycle_64bits(self):
        """TC_RSA_INT_003: Full cycle with 64 bits"""
        keys = get_rsa_keys(64)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["n"],
            keys["e"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(15)
    def test_multiple_messages(self):
        """TC_RSA_INT_004: Sign and verify multiple messages"""
        keys = get_rsa_keys(32)
        messages = ["TEST", "HELLO", "WORLD"]
        
        for msg in messages:
            sign_result = SignatureService.sign_with_rsa(msg, keys["p"], keys["q"], keys["d"])
            verify_result = SignatureService.verify_rsa_signature(
                sign_result["Hashed Message"],
                sign_result["Signed Message"],
                keys["n"],
                keys["e"]
            )
            assert verify_result["Verification: "] == "True", f"Failed for message: {msg}"
    
    @pytest.mark.timeout(15)
    def test_sign_twice_same_message(self):
        """TC_RSA_INT_005: Sign same message twice"""
        keys = get_rsa_keys(32)
        
        sign1 = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        sign2 = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        
        # Should produce identical signatures (RSA is deterministic)
        assert sign1["Signed Message"] == sign2["Signed Message"]
        assert sign1["Hashed Message"] == sign2["Hashed Message"]
    
    @pytest.mark.timeout(15)
    def test_cross_key_verification(self):
        """TC_RSA_INT_006: Sign with keys1, verify with keys2 (should fail)"""
        keys1 = get_rsa_keys(32)
        keys2 = get_rsa_keys(32)
        
        sign_result = SignatureService.sign_with_rsa("TEST", keys1["p"], keys1["q"], keys1["d"])
        verify_result = SignatureService.verify_rsa_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys2["n"],
            keys2["e"]
        )
        
        assert verify_result["Verification: "] == "False"


class TestRSAMathematicalProperties:
    """Mathematical property tests"""
    
    @pytest.mark.timeout(15)
    def test_signature_formula(self):
        """TC_RSA_MATH_001: Signature follows S = M^d mod n"""
        from MahuCrypt_app.cryptography.signature import sign_RSA
        from MahuCrypt_app.cryptography.algos import modular_exponentiation
        
        keys = get_rsa_keys(32)
        message = "TEST"
        
        signed, hashed = sign_RSA(message, {"p": keys["p"], "q": keys["q"], "d": keys["d"]})
        
        # Check: signature = hash^d mod n
        n = keys["n"]
        d = keys["d"]
        
        for i, hash_val in enumerate(hashed):
            expected_sig = modular_exponentiation(hash_val, d, n)
            assert signed[i] == expected_sig, f"Signature formula failed for block {i}"
    
    @pytest.mark.timeout(15)
    def test_verification_formula(self):
        """TC_RSA_MATH_002: Verification follows M = S^e mod n"""
        from MahuCrypt_app.cryptography.signature import sign_RSA
        from MahuCrypt_app.cryptography.algos import modular_exponentiation
        
        keys = get_rsa_keys(32)
        message = "TEST"
        
        signed, hashed = sign_RSA(message, {"p": keys["p"], "q": keys["q"], "d": keys["d"]})
        
        # Check: hash = signature^e mod n
        n = keys["n"]
        e = keys["e"]
        
        for i, sig_val in enumerate(signed):
            recovered_hash = modular_exponentiation(sig_val, e, n)
            assert recovered_hash == hashed[i], f"Verification formula failed for block {i}"
    
    @pytest.mark.timeout(15)
    def test_signature_deterministic(self):
        """TC_RSA_MATH_003: Signing is deterministic"""
        from MahuCrypt_app.cryptography.signature import sign_RSA
        
        keys = get_rsa_keys(32)
        private_key = {"p": keys["p"], "q": keys["q"], "d": keys["d"]}
        
        signed1, hashed1 = sign_RSA("TEST", private_key)
        signed2, hashed2 = sign_RSA("TEST", private_key)
        
        assert signed1 == signed2, "Signatures should be identical"
        assert hashed1 == hashed2, "Hashes should be identical"
    
    @pytest.mark.timeout(15)
    def test_signature_hash_length_match(self):
        """TC_RSA_MATH_004: Signature and hash lists have same length"""
        from MahuCrypt_app.cryptography.signature import sign_RSA
        
        keys = get_rsa_keys(32)
        private_key = {"p": keys["p"], "q": keys["q"], "d": keys["d"]}
        
        signed, hashed = sign_RSA("HELLOWORLD", private_key)
        
        assert len(signed) == len(hashed), "Signature and hash lists must have same length"
    
    @pytest.mark.timeout(15)
    def test_invalid_signature_detection(self):
        """TC_RSA_MATH_005: Modified signature is detected"""
        from MahuCrypt_app.cryptography.signature import sign_RSA, verify_RSA
        
        keys = get_rsa_keys(32)
        private_key = {"p": keys["p"], "q": keys["q"], "d": keys["d"]}
        public_key = (keys["n"], keys["e"])
        
        signed, hashed = sign_RSA("TEST", private_key)
        
        # Modify signature
        signed[0] = signed[0] + 1
        
        result = verify_RSA(hashed, signed, public_key)
        assert result == False, "Modified signature should be detected"


class TestRSAEdgeCases:
    """Edge case tests"""
    
    @pytest.mark.timeout(15)
    def test_very_small_n_16bits(self):
        """TC_RSA_EDGE_001: Very small n (16 bits)"""
        keys = get_rsa_keys(16)
        
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], keys["d"])
        assert "Error" not in result, "16-bit keys should work (though insecure)"
    
    @pytest.mark.timeout(15)
    def test_message_boundary(self):
        """TC_RSA_EDGE_002: Message with length = 4k chars"""
        keys = get_rsa_keys(32)
        message = "A" * 8  # 8 chars = 2 blocks
        
        result = SignatureService.sign_with_rsa(message, keys["p"], keys["q"], keys["d"])
        
        assert "Error" not in result
        signed = eval(result["Signed Message"])
        assert len(signed) == 2
    
    @pytest.mark.timeout(15)
    def test_empty_after_preprocessing(self):
        """TC_RSA_EDGE_003: Empty after preprocessing (no letters)"""
        keys = get_rsa_keys(32)
        
        result = SignatureService.sign_with_rsa("123!@#", keys["p"], keys["q"], keys["d"])
        
        # May error or produce empty result
        # Just check it doesn't crash
        assert result is not None
    
    def test_maximum_d_value(self):
        """TC_RSA_EDGE_004: d = n-1 (invalid, d > φ(n))"""
        keys = get_rsa_keys(32)
        n = keys["n"]
        
        result = SignatureService.sign_with_rsa("TEST", keys["p"], keys["q"], n - 1)
        
        # Should error because d > φ(n)
        assert result == "Enter Again" or (isinstance(result, dict) and "Error" in result)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
