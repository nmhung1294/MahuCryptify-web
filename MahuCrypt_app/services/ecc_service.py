"""
ECC Service - Business logic for Elliptic Curve Cryptography
"""

from MahuCrypt_app.cryptography.public_key_cryptography import (
    create_ECC_keys, EN_ECC, DE_ECC
)
from MahuCrypt_app.cryptography.algos import miller_rabin_test


class ECCService:
    """Service class for ECC operations"""
    
    @staticmethod
    def validate_key_generation_input(bits):
        """Validate input for ECC key generation"""
        if bits is None:
            return False, "NULL Value - Please enter bits"
        
        try:
            bits = int(bits)
        except (ValueError, TypeError):
            return False, "Bits must be an integer"
        
        if bits <= 1:
            return False, "Bits must be greater than 0"
        
        return True, None
    
    @staticmethod
    def generate_keys(bits):
        """Generate ECC key pair"""
        is_valid, error = ECCService.validate_key_generation_input(bits)
        if not is_valid:
            return {"Error": error}
        
        try:
            key_ECC = create_ECC_keys(bits)
            return key_ECC
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_encryption_input(message, a, p, P, B):
        """Validate input for ECC encryption"""
        if a is None or p is None or P is None or B is None or message is None:
            return False, "NULL Value"
        
        try:
            a = int(a)
            p = int(p)
            Px, Py = P
            Bx, By = B
        except (ValueError, TypeError):
            return False, "Invalid point format"
        
        if a == 0 or p == 0 or P == (0, 0) or B == (0, 0):
            return False, "NULL Value"
        
        if message == "":
            return False, "NULL Value"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        return True, None
    
    @staticmethod
    def encrypt(message, a, p, P, B):
        """Encrypt message using ECC"""
        is_valid, error = ECCService.validate_encryption_input(
            message, a, p, P, B
        )
        if not is_valid:
            return {"Error": error}
        
        try:
            result = EN_ECC(message, {"a": a, "p": p, "P": P, "B": B})
            return result
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_decryption_input(encrypted_message, a, p, s):
        """Validate input for ECC decryption"""
        if encrypted_message is None or encrypted_message == "":
            return False, "NULL Value"
        
        if a is None or p is None or s is None:
            return False, "NULL Value"
        
        try:
            a = int(a)
            p = int(p)
            s = int(s)
        except (ValueError, TypeError):
            return False, "a, p, s must be integers"
        
        if a == 0 or p == 0 or s == 0:
            return False, "NULL Value"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        return True, None
    
    @staticmethod
    def decrypt(encrypted_message, a, p, s):
        """Decrypt message using ECC"""
        is_valid, error = ECCService.validate_decryption_input(
            encrypted_message, a, p, s
        )
        if not is_valid:
            return {"Error": error}
        
        try:
            result = DE_ECC(encrypted_message, {"a": a, "p": p}, s)
            return result
        except Exception as e:
            return {"Error": str(e)}
