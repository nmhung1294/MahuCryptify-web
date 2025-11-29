"""
ElGamal Service - Business logic for ElGamal cryptosystem
"""

from MahuCrypt_app.cryptography.public_key_cryptography import (
    create_ELGAMAL_keys, EN_ELGAMAL, DE_ELGAMAL
)
from MahuCrypt_app.cryptography.algos import miller_rabin_test, is_primitive_root


class ElGamalService:
    """Service class for ElGamal operations"""
    
    @staticmethod
    def validate_key_generation_input(bits):
        """Validate input for ElGamal key generation"""
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
        """Generate ElGamal key pair"""
        is_valid, error = ElGamalService.validate_key_generation_input(bits)
        if not is_valid:
            return {"Error": error}
        
        try:
            key_ElGamal = create_ELGAMAL_keys(bits)
            return key_ElGamal
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_encryption_input(message, p, alpha, beta):
        """Validate input for ElGamal encryption"""
        if p is None or alpha is None or beta is None or message is None:
            return False, "NULL Value"
        
        try:
            p = int(p)
            alpha = int(alpha)
            beta = int(beta)
        except (ValueError, TypeError):
            return False, "p, alpha, beta must be integers"
        
        if p <= 0 or alpha <= 0 or beta <= 0:
            return False, "NULL Value"
        
        if message == "":
            return False, "NULL Value"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        if not is_primitive_root(alpha, p):
            return False, "alpha is not primitive root"
        
        return True, None
    
    @staticmethod
    def encrypt(message, p, alpha, beta):
        """Encrypt message using ElGamal"""
        is_valid, error = ElGamalService.validate_encryption_input(
            message, p, alpha, beta
        )
        if not is_valid:
            return {"Error": error}
        
        try:
            encrypted_message = EN_ELGAMAL(message, {"p": p, "alpha": alpha, "beta": beta})
            return encrypted_message
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_decryption_input(encrypted_message, p, a):
        """Validate input for ElGamal decryption"""
        if encrypted_message is None or encrypted_message == "":
            return False, "Enter Again"
        
        if p is None or a is None:
            return False, "Enter Again"
        
        try:
            p = int(p)
            a = int(a)
        except (ValueError, TypeError):
            return False, "p and a must be integers"
        
        if p == 0 or a == 0:
            return False, "Enter Again"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        return True, None
    
    @staticmethod
    def decrypt(encrypted_message, p, a):
        """Decrypt message using ElGamal"""
        is_valid, error = ElGamalService.validate_decryption_input(
            encrypted_message, p, a
        )
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            decrypted_message = DE_ELGAMAL(encrypted_message, p, a)
            return decrypted_message
        except Exception as e:
            return {"Error": str(e)}
