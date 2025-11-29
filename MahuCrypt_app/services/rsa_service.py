"""
RSA Service - Business logic for RSA cryptosystem
Separated from API controllers for better testability
"""

from MahuCrypt_app.cryptography.public_key_cryptography import (
    create_RSA_keys, EN_RSA, DE_RSA
)
from MahuCrypt_app.cryptography.algos import miller_rabin_test


class RSAService:
    """Service class for RSA operations"""
    
    @staticmethod
    def validate_key_generation_input(bits):
        """
        Validate input for RSA key generation
        
        Args:
            bits (int): Number of bits for prime generation
            
        Returns:
            tuple: (is_valid, error_message)
        """
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
        """
        Generate RSA key pair
        
        Args:
            bits (int): Number of bits for prime generation
            
        Returns:
            dict: RSA keys or error
        """
        is_valid, error = RSAService.validate_key_generation_input(bits)
        if not is_valid:
            return {"Error": error}
        
        try:
            key_RSA = create_RSA_keys(bits)
            return key_RSA
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_encryption_input(message, n, e):
        """
        Validate input for RSA encryption
        
        Args:
            message (str): Message to encrypt
            n (int): RSA modulus
            e (int): Public exponent
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if n is None or e is None or message is None:
            return False, "NULL Value"
        
        try:
            n = int(n)
            e = int(e)
        except (ValueError, TypeError):
            return False, "n and e must be integers"
        
        if n <= 0 or e <= 0:
            return False, "NULL Value"
        
        if e > n:
            return False, "NULL Value"
        
        if message == "":
            return False, "NULL Value"
        
        return True, None
    
    @staticmethod
    def encrypt(message, n, e):
        """
        Encrypt message using RSA
        
        Args:
            message (str): Message to encrypt
            n (int): RSA modulus
            e (int): Public exponent
            
        Returns:
            dict: Encrypted message or error
        """
        is_valid, error = RSAService.validate_encryption_input(message, n, e)
        if not is_valid:
            return {"Error": error}
        
        try:
            encrypted_message = EN_RSA(message, (n, e))
            return encrypted_message
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_decryption_input(encrypted_message, p, q, d):
        """
        Validate input for RSA decryption
        
        Args:
            encrypted_message (str): Encrypted message
            p (int): Prime p
            q (int): Prime q
            d (int): Private exponent
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if encrypted_message is None or encrypted_message == "":
            return False, "NULL Value"
        
        if p is None or q is None or d is None:
            return False, "NULL Value"
        
        try:
            p = int(p)
            q = int(q)
            d = int(d)
        except (ValueError, TypeError):
            return False, "p, q, d must be integers"
        
        if p == 0 or q == 0 or d == 0:
            return False, "NULL Value"
        
        if d > p * q:
            return False, "Invalid d"
        
        if not miller_rabin_test(p, 1000):
            return False, "p or q is not prime"
        
        if not miller_rabin_test(q, 1000):
            return False, "p or q is not prime"
        
        return True, None
    
    @staticmethod
    def decrypt(encrypted_message, p, q, d):
        """
        Decrypt message using RSA
        
        Args:
            encrypted_message (str): Encrypted message
            p (int): Prime p
            q (int): Prime q
            d (int): Private exponent
            
        Returns:
            dict: Decrypted message or error
        """
        is_valid, error = RSAService.validate_decryption_input(
            encrypted_message, p, q, d
        )
        if not is_valid:
            return {"Error": error}
        
        try:
            decrypted_message = DE_RSA(encrypted_message, {"p": p, "q": q, "d": d})
            return decrypted_message
        except Exception as e:
            return {"Error": str(e)}
