"""
Classical Cryptography Service - Business logic for classical ciphers
"""

from MahuCrypt_app.cryptography.classical_cryptography import (
    En_Shift_Cipher, De_Shift_Cipher,
    En_Affine_Cipher, De_Affine_Cipher,
    En_Vigenere_Cipher, De_Vigenere_Cipher,
    En_Hill_Cipher, De_Hill_Cipher
)


class ClassicalService:
    """Service class for classical cipher operations"""
    
    # Shift Cipher
    @staticmethod
    def validate_shift_cipher_input(message, key):
        """Validate input for Shift Cipher"""
        if message is None or key is None:
            return False, "NULL Value"
        
        try:
            key = int(key)
        except (ValueError, TypeError):
            return False, "Key must be an integer"
        
        return True, None
    
    @staticmethod
    def encrypt_shift(message, key):
        """Encrypt using Shift Cipher"""
        is_valid, error = ClassicalService.validate_shift_cipher_input(message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return En_Shift_Cipher(message, key)
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def decrypt_shift(encrypted_message, key):
        """Decrypt using Shift Cipher"""
        is_valid, error = ClassicalService.validate_shift_cipher_input(encrypted_message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return De_Shift_Cipher(encrypted_message, key)
        except Exception as e:
            return {"Error": str(e)}
    
    # Affine Cipher
    @staticmethod
    def validate_affine_cipher_input(message, a, b):
        """Validate input for Affine Cipher"""
        if message is None or a is None or b is None:
            return False, "NULL Value"
        
        try:
            a = int(a)
            b = int(b)
        except (ValueError, TypeError):
            return False, "a and b must be integers"
        
        if a == 0 or b == 0:
            return False, "NULL Value"
        
        return True, None
    
    @staticmethod
    def encrypt_affine(message, a, b):
        """Encrypt using Affine Cipher"""
        is_valid, error = ClassicalService.validate_affine_cipher_input(message, a, b)
        if not is_valid:
            return {"Error": error}
        
        try:
            return En_Affine_Cipher(message, a, b)
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def decrypt_affine(encrypted_message, a, b):
        """Decrypt using Affine Cipher"""
        is_valid, error = ClassicalService.validate_affine_cipher_input(encrypted_message, a, b)
        if not is_valid:
            return {"Error": error}
        
        try:
            return De_Affine_Cipher(encrypted_message, a, b)
        except Exception as e:
            return {"Error": str(e)}
    
    # Vigenère Cipher
    @staticmethod
    def validate_vigenere_cipher_input(message, key):
        """Validate input for Vigenère Cipher"""
        if message is None or key is None:
            return False, "NULL Value"
        
        if key == "":
            return False, "Key cannot be empty"
        
        return True, None
    
    @staticmethod
    def encrypt_vigenere(message, key):
        """Encrypt using Vigenère Cipher"""
        is_valid, error = ClassicalService.validate_vigenere_cipher_input(message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return En_Vigenere_Cipher(message, key)
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def decrypt_vigenere(encrypted_message, key):
        """Decrypt using Vigenère Cipher"""
        is_valid, error = ClassicalService.validate_vigenere_cipher_input(encrypted_message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return De_Vigenere_Cipher(encrypted_message, key)
        except Exception as e:
            return {"Error": str(e)}
    
    # Hill Cipher
    @staticmethod
    def validate_hill_cipher_input(message, key):
        """Validate input for Hill Cipher"""
        if message is None or key is None:
            return False, "NULL Value"
        
        if key == "":
            return False, "Key cannot be empty"
        
        return True, None
    
    @staticmethod
    def encrypt_hill(message, key):
        """Encrypt using Hill Cipher"""
        is_valid, error = ClassicalService.validate_hill_cipher_input(message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return En_Hill_Cipher(message, key)
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def decrypt_hill(encrypted_message, key):
        """Decrypt using Hill Cipher"""
        is_valid, error = ClassicalService.validate_hill_cipher_input(encrypted_message, key)
        if not is_valid:
            return {"Error": error}
        
        try:
            return De_Hill_Cipher(encrypted_message, key)
        except Exception as e:
            return {"Error": str(e)}
