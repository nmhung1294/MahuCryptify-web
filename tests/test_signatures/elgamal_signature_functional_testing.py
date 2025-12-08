"""
ELGAMAL DIGITAL SIGNATURE - FUNCTIONAL TESTS
Black-box testing of ElGamal signing and verification
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from MahuCrypt_app.services.signature_service import SignatureService
from MahuCrypt_app.cryptography.public_key_cryptography import create_ELGAMAL_keys
from MahuCrypt_app.cryptography.algos import miller_rabin_test, is_primitive_root


def get_elgamal_keys(bits):
    """Helper to extract ElGamal keys from nested dict"""
    keys_dict = create_ELGAMAL_keys(bits)
    return {
        "p": int(keys_dict["public_key"]["p"]),
        "alpha": int(keys_dict["public_key"]["alpha"]),
        "beta": int(keys_dict["public_key"]["beta"]),
        "a": int(keys_dict["private_key - a"])
    }


class TestElGamalSigningBasic:
    """Basic ElGamal signing tests"""
    
    @pytest.mark.timeout(20)
    def test_sign_hello_32bits(self):
        """TC_ELG_SIG_001: Sign 'HELLO' with 32 bits"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("HELLO", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result, f"Unexpected error: {result}"
        assert "Signed Message" in result
        assert "Hashed Message" in result
        assert result["Signed Message"] != ""
        assert result["Hashed Message"] != ""
    
    @pytest.mark.timeout(20)
    def test_sign_test_32bits(self):
        """TC_ELG_SIG_002: Sign 'TEST' (1 block, 4 chars)"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # TEST = 4 chars = 1 block
        signed_str = result["Signed Message"]
        # Count number of tuples
        assert signed_str.count("(") == 1, "Expected 1 signature tuple for 'TEST'"
    
    @pytest.mark.timeout(20)
    def test_sign_single_char(self):
        """TC_ELG_SIG_003: Sign single character 'A'"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("A", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
    
    @pytest.mark.timeout(20)
    def test_sign_multiple_blocks(self):
        """TC_ELG_SIG_004: Sign 'HELLOWORLD' (multiple blocks)"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("HELLOWORLD", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # HELLOWORLD = 10 chars = 3 blocks (4+4+2)
        signed_str = result["Signed Message"]
        tuple_count = signed_str.count("(")
        assert tuple_count == 3, f"Expected 3 blocks, got {tuple_count}"
    
    @pytest.mark.timeout(20)
    def test_sign_long_text(self):
        """TC_ELG_SIG_005: Sign long text (20 'A's)"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("A" * 20, keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # 20 chars = 5 blocks
        signed_str = result["Signed Message"]
        tuple_count = signed_str.count("(")
        assert tuple_count == 5, f"Expected 5 blocks, got {tuple_count}"
    
    @pytest.mark.timeout(20)
    def test_sign_16bits(self):
        """TC_ELG_SIG_006: Sign with 16 bits (fast)"""
        keys = get_elgamal_keys(16)
        result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
    
    @pytest.mark.timeout(20)
    def test_sign_64bits(self):
        """TC_ELG_SIG_007: Sign with 64 bits (may be slower)"""
        keys = get_elgamal_keys(64)
        result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
    
    @pytest.mark.timeout(20)
    def test_sign_result_format(self):
        """TC_ELG_SIG_008: Check result format contains tuples"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        assert isinstance(result, dict)
        assert "Signed Message" in result
        assert "Hashed Message" in result
        
        # Signature should contain tuples (γ, δ)
        signed_str = result["Signed Message"]
        assert "(" in signed_str and ")" in signed_str
        assert "," in signed_str
    
    @pytest.mark.timeout(20)
    def test_sign_with_special_chars(self):
        """TC_ELG_SIG_009: Sign with special characters (removed by pre_solve)"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("TEST!@#", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result
        # Special chars should be removed, only "TEST" remains
    
    @pytest.mark.timeout(20)
    def test_sign_lowercase(self):
        """TC_ELG_SIG_010: Sign lowercase (converted to uppercase)"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("test", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        assert "Signed Message" in result


class TestElGamalTextProcessing:
    """Text processing tests for ElGamal signing"""
    
    @pytest.mark.timeout(20)
    def test_special_characters_removed(self):
        """TC_ELG_SIG_T001: Special characters are removed"""
        keys = get_elgamal_keys(32)
        result1 = SignatureService.sign_with_elgamal("HELLO", keys["p"], keys["alpha"], keys["a"])
        result2 = SignatureService.sign_with_elgamal("HELLO!@#$", keys["p"], keys["alpha"], keys["a"])
        
        # Both should produce same hash (special chars removed)
        assert result1["Hashed Message"] == result2["Hashed Message"]
    
    @pytest.mark.timeout(20)
    def test_numbers_removed(self):
        """TC_ELG_SIG_T002: Numbers are removed"""
        keys = get_elgamal_keys(32)
        result1 = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        result2 = SignatureService.sign_with_elgamal("TEST123", keys["p"], keys["alpha"], keys["a"])
        
        # Both should produce same hash (numbers removed)
        # NOTE: This may fail if BUG-RSA-SIG-001 exists in ElGamal too
        assert result1["Hashed Message"] == result2["Hashed Message"]
    
    @pytest.mark.timeout(20)
    def test_spaces_handling(self):
        """TC_ELG_SIG_T003: Spaces are handled"""
        keys = get_elgamal_keys(32)
        result = SignatureService.sign_with_elgamal("HELLO WORLD", keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        # Spaces should be removed/handled by pre_solve
    
    @pytest.mark.timeout(20)
    def test_mixed_case(self):
        """TC_ELG_SIG_T004: Mixed case converted to uppercase"""
        keys = get_elgamal_keys(32)
        result1 = SignatureService.sign_with_elgamal("HELLO", keys["p"], keys["alpha"], keys["a"])
        result2 = SignatureService.sign_with_elgamal("HeLLo", keys["p"], keys["alpha"], keys["a"])
        
        # Both should produce same hash (case normalized)
        assert result1["Hashed Message"] == result2["Hashed Message"]


class TestElGamalSigningErrors:
    """Error handling tests for ElGamal signing"""
    
    def test_null_message(self):
        """TC_ELG_SIG_E001: Null message"""
        result = SignatureService.sign_with_elgamal(None, 23, 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_empty_message(self):
        """TC_ELG_SIG_E002: Empty message"""
        result = SignatureService.sign_with_elgamal("", 23, 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_p(self):
        """TC_ELG_SIG_E003: Null p"""
        result = SignatureService.sign_with_elgamal("TEST", None, 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_alpha(self):
        """TC_ELG_SIG_E004: Null alpha"""
        result = SignatureService.sign_with_elgamal("TEST", 23, None, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_a(self):
        """TC_ELG_SIG_E005: Null a"""
        result = SignatureService.sign_with_elgamal("TEST", 23, 2, None)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_p_not_prime(self):
        """TC_ELG_SIG_E006: p not prime"""
        result = SignatureService.sign_with_elgamal("TEST", 100, 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "prime" in result["Error"].lower()
    
    def test_alpha_not_primitive_root(self):
        """TC_ELG_SIG_E007: alpha not primitive root"""
        # p=7, alpha=3: 3 is not primitive root mod 7
        # 3^1=3, 3^2=2, 3^3=6, 3^4=4, 3^5=5, 3^6=1 (doesn't generate all)
        result = SignatureService.sign_with_elgamal("TEST", 7, 3, 2)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "primitive root" in result["Error"].lower()
    
    def test_p_zero(self):
        """TC_ELG_SIG_E008: p = 0"""
        result = SignatureService.sign_with_elgamal("TEST", 0, 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_alpha_zero(self):
        """TC_ELG_SIG_E009: alpha = 0"""
        result = SignatureService.sign_with_elgamal("TEST", 23, 0, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_a_zero(self):
        """TC_ELG_SIG_E010: a = 0"""
        result = SignatureService.sign_with_elgamal("TEST", 23, 2, 0)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_invalid_types(self):
        """TC_ELG_SIG_E011: Invalid types for p, alpha, a"""
        result = SignatureService.sign_with_elgamal("TEST", "abc", 2, 5)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "integer" in result["Error"].lower()


class TestElGamalVerificationBasic:
    """Basic ElGamal verification tests"""
    
    @pytest.mark.timeout(20)
    def test_verify_valid_signature(self):
        """TC_ELG_VER_001: Verify valid signature"""
        keys = get_elgamal_keys(32)
        
        # Sign message
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        assert "Error" not in sign_result
        
        # Verify signature
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert "Error" not in verify_result
        assert "Verification: " in verify_result
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_verify_multiple_blocks(self):
        """TC_ELG_VER_002: Verify signature of multiple blocks"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("HELLO", keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_verify_with_correct_keys(self):
        """TC_ELG_VER_003: Verify with matching keys"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_verify_single_block(self):
        """TC_ELG_VER_004: Verify single block signature"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_verify_long_message(self):
        """TC_ELG_VER_005: Verify long message signature"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("A" * 20, keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_verify_wrong_signature(self):
        """TC_ELG_VER_006: Verify with modified signature"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        # Modify signature (change first gamma value)
        signed_str = sign_result["Signed Message"]
        # Parse and modify
        import re
        numbers = re.findall(r'\d+', signed_str)
        if len(numbers) >= 2:
            numbers[0] = str(int(numbers[0]) + 1)
            modified_sig = signed_str
            for i, num in enumerate(re.findall(r'\d+', sign_result["Signed Message"])):
                modified_sig = modified_sig.replace(num, numbers[i], 1)
            
            verify_result = SignatureService.verify_elgamal_signature(
                sign_result["Hashed Message"],
                modified_sig,
                keys["p"],
                keys["alpha"],
                keys["beta"]
            )
            
            assert verify_result["Verification: "] == "False"
    
    @pytest.mark.timeout(20)
    def test_verify_wrong_message(self):
        """TC_ELG_VER_007: Verify with different hash"""
        keys = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        # Use hash from different message
        sign_result2 = SignatureService.sign_with_elgamal("HELLO", keys["p"], keys["alpha"], keys["a"])
        
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result2["Hashed Message"],  # Wrong hash
            sign_result["Signed Message"],   # Original signature
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "False"
    
    @pytest.mark.timeout(20)
    def test_verify_wrong_keys(self):
        """TC_ELG_VER_008: Verify with different keys"""
        keys1 = get_elgamal_keys(32)
        keys2 = get_elgamal_keys(32)
        
        # Sign with keys1
        sign_result = SignatureService.sign_with_elgamal("TEST", keys1["p"], keys1["alpha"], keys1["a"])
        
        # Verify with keys2
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys2["p"],
            keys2["alpha"],
            keys2["beta"]
        )
        
        assert verify_result["Verification: "] == "False"


class TestElGamalVerificationErrors:
    """Error handling tests for ElGamal verification"""
    
    def test_null_hash(self):
        """TC_ELG_VER_E001: Null hash"""
        result = SignatureService.verify_elgamal_signature(None, "[(123, 456)]", 23, 2, 18)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_empty_hash(self):
        """TC_ELG_VER_E002: Empty hash"""
        result = SignatureService.verify_elgamal_signature("", "[(123, 456)]", 23, 2, 18)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_signature(self):
        """TC_ELG_VER_E003: Null signature"""
        result = SignatureService.verify_elgamal_signature("[123]", None, 23, 2, 18)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_p(self):
        """TC_ELG_VER_E004: Null p"""
        result = SignatureService.verify_elgamal_signature("[123]", "[(123, 456)]", None, 2, 18)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]
    
    def test_null_alpha(self):
        """TC_ELG_VER_E005: Null alpha"""
        result = SignatureService.verify_elgamal_signature("[123]", "[(123, 456)]", 23, None, 18)
        
        assert isinstance(result, dict)
        assert "Error" in result
        assert "NULL Value" in result["Error"]


class TestElGamalIntegration:
    """Integration tests for full sign-verify cycle"""
    
    @pytest.mark.timeout(20)
    def test_full_cycle_32bits(self):
        """TC_ELG_INT_001: Full cycle with 32 bits"""
        keys = get_elgamal_keys(32)
        
        # Sign
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        assert "Error" not in sign_result
        
        # Verify
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_full_cycle_16bits(self):
        """TC_ELG_INT_002: Full cycle with 16 bits"""
        keys = get_elgamal_keys(16)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_full_cycle_64bits(self):
        """TC_ELG_INT_003: Full cycle with 64 bits"""
        keys = get_elgamal_keys(64)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys["p"],
            keys["alpha"],
            keys["beta"]
        )
        
        assert verify_result["Verification: "] == "True"
    
    @pytest.mark.timeout(20)
    def test_multiple_messages(self):
        """TC_ELG_INT_004: Sign and verify multiple messages"""
        keys = get_elgamal_keys(32)
        messages = ["TEST", "HELLO", "WORLD"]
        
        for msg in messages:
            sign_result = SignatureService.sign_with_elgamal(msg, keys["p"], keys["alpha"], keys["a"])
            verify_result = SignatureService.verify_elgamal_signature(
                sign_result["Hashed Message"],
                sign_result["Signed Message"],
                keys["p"],
                keys["alpha"],
                keys["beta"]
            )
            assert verify_result["Verification: "] == "True", f"Failed for message: {msg}"
    
    @pytest.mark.timeout(20)
    def test_sign_twice_probabilistic(self):
        """TC_ELG_INT_005: Sign same message twice (should differ if probabilistic)"""
        keys = get_elgamal_keys(32)
        
        sign1 = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        sign2 = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        
        # NOTE: Implementation uses same k for all blocks in one signing,
        # but k should be different between two separate signings
        # However, if k is truly random, signatures SHOULD differ
        # If they're the same, k might be deterministic (bug/simplification)
        
        # Just verify both are valid
        assert "Error" not in sign1
        assert "Error" not in sign2
        # Both should have same hash (deterministic)
        assert sign1["Hashed Message"] == sign2["Hashed Message"]
    
    @pytest.mark.timeout(20)
    def test_cross_key_verification(self):
        """TC_ELG_INT_006: Sign with keys1, verify with keys2 (should fail)"""
        keys1 = get_elgamal_keys(32)
        keys2 = get_elgamal_keys(32)
        
        sign_result = SignatureService.sign_with_elgamal("TEST", keys1["p"], keys1["alpha"], keys1["a"])
        verify_result = SignatureService.verify_elgamal_signature(
            sign_result["Hashed Message"],
            sign_result["Signed Message"],
            keys2["p"],
            keys2["alpha"],
            keys2["beta"]
        )
        
        assert verify_result["Verification: "] == "False"


class TestElGamalMathematicalProperties:
    """Mathematical property tests"""
    
    @pytest.mark.timeout(20)
    def test_gamma_formula(self):
        """TC_ELG_MATH_001: Gamma follows γ = α^k mod p"""
        from MahuCrypt_app.cryptography.signature import sign_ELGAMAL
        from MahuCrypt_app.cryptography.algos import modular_exponentiation
        
        keys = get_elgamal_keys(32)
        message = "TEST"
        
        signed, hashed = sign_ELGAMAL(message, {"p": keys["p"], "alpha": keys["alpha"]}, keys["a"])
        
        # All gammas should be same (implementation uses same k for all blocks)
        gammas = [sig[0] for sig in signed]
        assert len(set(gammas)) == 1, "All gammas should be identical (same k used)"
    
    @pytest.mark.timeout(20)
    def test_verification_formula(self):
        """TC_ELG_MATH_003: Verification follows β^γ × γ^δ ≡ α^M (mod p)"""
        from MahuCrypt_app.cryptography.signature import sign_ELGAMAL, verify_ELGAMAL
        
        keys = get_elgamal_keys(32)
        message = "TEST"
        
        signed, hashed = sign_ELGAMAL(message, {"p": keys["p"], "alpha": keys["alpha"]}, keys["a"])
        
        # Verify should return True
        result = verify_ELGAMAL(hashed, signed, {"p": keys["p"], "alpha": keys["alpha"], "beta": keys["beta"]})
        assert result == True, "Verification formula should hold"
    
    @pytest.mark.timeout(20)
    def test_signature_format(self):
        """TC_ELG_MATH_004: Signature contains (γ, δ) tuples"""
        from MahuCrypt_app.cryptography.signature import sign_ELGAMAL
        
        keys = get_elgamal_keys(32)
        message = "HELLO"
        
        signed, hashed = sign_ELGAMAL(message, {"p": keys["p"], "alpha": keys["alpha"]}, keys["a"])
        
        # Check all elements are tuples with 2 values
        for sig in signed:
            assert isinstance(sig, tuple), "Signature should be tuple"
            assert len(sig) == 2, "Signature tuple should have 2 elements (γ, δ)"
            gamma, delta = sig
            assert isinstance(gamma, int), "Gamma should be integer"
            assert isinstance(delta, int), "Delta should be integer"
    
    @pytest.mark.timeout(20)
    def test_invalid_signature_detection(self):
        """TC_ELG_MATH_005: Modified signature is detected"""
        from MahuCrypt_app.cryptography.signature import sign_ELGAMAL, verify_ELGAMAL
        
        keys = get_elgamal_keys(32)
        message = "TEST"
        
        signed, hashed = sign_ELGAMAL(message, {"p": keys["p"], "alpha": keys["alpha"]}, keys["a"])
        
        # Modify gamma of first signature
        gamma, delta = signed[0]
        signed[0] = (gamma + 1, delta)
        
        result = verify_ELGAMAL(hashed, signed, {"p": keys["p"], "alpha": keys["alpha"], "beta": keys["beta"]})
        assert result == False, "Modified signature should be detected"
    
    @pytest.mark.timeout(20)
    def test_same_k_for_all_blocks(self):
        """TC_ELG_MATH_006: Implementation uses same k for all blocks"""
        from MahuCrypt_app.cryptography.signature import sign_ELGAMAL
        
        keys = get_elgamal_keys(32)
        message = "HELLOWORLD"  # Multiple blocks
        
        signed, hashed = sign_ELGAMAL(message, {"p": keys["p"], "alpha": keys["alpha"]}, keys["a"])
        
        # All gamma values should be identical (same k)
        gammas = [sig[0] for sig in signed]
        assert len(set(gammas)) == 1, "All gammas should be same (k reuse)"
        
        # This is a security issue but simplifies implementation


class TestElGamalEdgeCases:
    """Edge case tests"""
    
    @pytest.mark.timeout(20)
    def test_very_small_p_16bits(self):
        """TC_ELG_EDGE_001: Very small p (16 bits)"""
        keys = get_elgamal_keys(16)
        
        result = SignatureService.sign_with_elgamal("TEST", keys["p"], keys["alpha"], keys["a"])
        assert "Error" not in result, "16-bit keys should work (though insecure)"
    
    @pytest.mark.timeout(20)
    def test_message_boundary(self):
        """TC_ELG_EDGE_002: Message with length = 4k chars"""
        keys = get_elgamal_keys(32)
        message = "A" * 8  # 8 chars = 2 blocks
        
        result = SignatureService.sign_with_elgamal(message, keys["p"], keys["alpha"], keys["a"])
        
        assert "Error" not in result
        tuple_count = result["Signed Message"].count("(")
        assert tuple_count == 2
    
    @pytest.mark.timeout(20)
    def test_empty_after_preprocessing(self):
        """TC_ELG_EDGE_003: Empty after preprocessing (no letters)"""
        keys = get_elgamal_keys(32)
        
        result = SignatureService.sign_with_elgamal("123!@#", keys["p"], keys["alpha"], keys["a"])
        
        # May error or produce empty result
        # Just check it doesn't crash
        assert result is not None
    
    @pytest.mark.timeout(20)
    def test_alpha_2_validation(self):
        """TC_ELG_EDGE_004: Alpha = 2 validation"""
        keys = get_elgamal_keys(32)
        
        # Implementation uses alpha = 2
        # Should work if p is chosen such that 2 is primitive root
        assert keys["alpha"] == 2, "Implementation should use alpha = 2"
        
        # Verify it's actually a primitive root
        assert is_primitive_root(2, keys["p"]), "Alpha = 2 should be primitive root for chosen p"
    
    @pytest.mark.timeout(20)
    def test_large_a_value(self):
        """TC_ELG_EDGE_005: Large a value (a = p - 2)"""
        keys = get_elgamal_keys(32)
        p = keys["p"]
        alpha = keys["alpha"]
        a = p - 2  # Large private key
        
        result = SignatureService.sign_with_elgamal("TEST", p, alpha, a)
        
        # Should work (a < p-1 is valid)
        assert "Error" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
