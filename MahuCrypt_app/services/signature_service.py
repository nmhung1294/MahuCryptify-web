"""
Digital Signature Service - Business logic for digital signatures
"""

from MahuCrypt_app.cryptography.signature import (
    sign_RSA, verify_RSA,
    sign_ELGAMAL, verify_ELGAMAL,
    sign_ECDSA, verify_ECDSA
)
from MahuCrypt_app.cryptography.public_key_cryptography import (
    create_RSA_keys, create_ELGAMAL_keys, create_ECC_keys, create_ECDSA_keys
)
from MahuCrypt_app.cryptography.algos import miller_rabin_test, is_primitive_root, is_point_on_curve


class SignatureService:
    """Service class for digital signature operations"""
    
    # RSA Signature
    @staticmethod
    def validate_rsa_sign_input(message, p, q, d):
        """Validate input for RSA signing"""
        if message is None or message == "":
            return False, "Enter Again"
        
        if p is None or q is None or d is None:
            return False, "Enter Again"
        
        try:
            p = int(p)
            q = int(q)
            d = int(d)
        except (ValueError, TypeError):
            return False, "p, q, d must be integers"
        
        if p == 0 or q == 0 or d == 0:
            return False, "Enter Again"
        
        if d > p * q:
            return False, "Enter Again"
        
        if not miller_rabin_test(p, 1000):
            return False, "p or q is not prime"
        
        if not miller_rabin_test(q, 1000):
            return False, "p or q is not prime"
        
        return True, None
    
    @staticmethod
    def sign_with_rsa(message, p, q, d):
        """Sign message using RSA"""
        is_valid, error = SignatureService.validate_rsa_sign_input(message, p, q, d)
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            signed_message, hash_message = sign_RSA(message, {"p": p, "q": q, "d": d})
            return {"Signed Message": str(signed_message), "Hashed Message": str(hash_message)}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_rsa_verify_input(hash_message_str, signed_message_str, n, e):
        """Validate input for RSA verification"""
        if hash_message_str is None or hash_message_str == "":
            return False, "Enter Again"
        
        if signed_message_str is None or signed_message_str == "":
            return False, "Enter Again"
        
        if n is None or e is None:
            return False, "Enter Again"
        
        try:
            n = int(n)
            e = int(e)
        except (ValueError, TypeError):
            return False, "n and e must be integers"
        
        if n == 0 or e == 0:
            return False, "Enter Again"
        
        if e > n:
            return False, "Enter Again"
        
        return True, None
    
    @staticmethod
    def verify_rsa_signature(hash_message_str, signed_message_str, n, e):
        """Verify RSA signature"""
        is_valid, error = SignatureService.validate_rsa_verify_input(
            hash_message_str, signed_message_str, n, e
        )
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            # Parse arrays
            signed_message_str = signed_message_str.strip("[]")
            signed_message = [int(sub_str) for sub_str in signed_message_str.split(",")]
            
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            
            result = verify_RSA(hash_message, signed_message, (n, e))
            return {"Verification: ": str(result)}
        except Exception as e:
            return {"Error": str(e)}
    
    # ElGamal Signature
    @staticmethod
    def validate_elgamal_sign_input(message, p, alpha, a):
        """Validate input for ElGamal signing"""
        if message is None or message == "":
            return False, "NULL Value"
        
        if p is None or alpha is None or a is None:
            return False, "NULL Value"
        
        try:
            p = int(p)
            alpha = int(alpha)
            a = int(a)
        except (ValueError, TypeError):
            return False, "p, alpha, a must be integers"
        
        if p == 0 or alpha == 0 or a == 0:
            return False, "NULL Value"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        if not is_primitive_root(alpha, p):
            return False, "alpha is not primitive root"
        
        return True, None
    
    @staticmethod
    def sign_with_elgamal(message, p, alpha, a):
        """Sign message using ElGamal"""
        is_valid, error = SignatureService.validate_elgamal_sign_input(message, p, alpha, a)
        if not is_valid:
            return {"Error": error}
        
        try:
            signed_message, hash_message = sign_ELGAMAL(message, {"p": p, "alpha": alpha}, a)
            return {"Signed Message": str(signed_message), "Hashed Message": str(hash_message)}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_elgamal_verify_input(hash_message_str, signed_message_str, p, alpha, beta):
        """Validate input for ElGamal verification"""
        if hash_message_str is None or hash_message_str == "":
            return False, "NULL Value"
        
        if signed_message_str is None or signed_message_str == "":
            return False, "NULL Value"
        
        if p is None or alpha is None or beta is None:
            return False, "NULL Value"
        
        try:
            p = int(p)
            alpha = int(alpha)
            beta = int(beta)
        except (ValueError, TypeError):
            return False, "p, alpha, beta must be integers"
        
        if p == 0 or alpha == 0 or beta == 0:
            return False, "NULL Value"
        
        if not miller_rabin_test(p, 1000):
            return False, "p is not prime"
        
        if not is_primitive_root(alpha, p):
            return False, "alpha is not primitive root"
        
        return True, None
    
    @staticmethod
    def verify_elgamal_signature(hash_message_str, signed_message_str, p, alpha, beta):
        """Verify ElGamal signature"""
        is_valid, error = SignatureService.validate_elgamal_verify_input(
            hash_message_str, signed_message_str, p, alpha, beta
        )
        if not is_valid:
            return {"Error": error}
        
        try:
            # Parse arrays
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            
            signed_message_str = signed_message_str.strip("[]")
            signed_message_str_list = signed_message_str.replace("(", "").replace(")", "").split("),(")
            signed_message_tmp = [int(sub_str) for sub_str in signed_message_str_list[0].split(",")]
            signed_message = []
            for i in range(0, len(signed_message_tmp) - 1, 2):
                signed_message.append((signed_message_tmp[i], signed_message_tmp[i + 1]))
            
            result = verify_ELGAMAL(hash_message, signed_message, {"p": p, "alpha": alpha, "beta": beta})
            return {"Verification: ": str(result)}
        except Exception as e:
            return {"Error": str(e)}
    
    # ECDSA
    @staticmethod
    def create_ecdsa_keys(bits):
        """Create ECDSA keys from ECC keys"""
        try:
            bits = int(bits)
        except (ValueError, TypeError):
            return {"Error": "Bits must be an integer"}
        
        if bits <= 1:
            return "Enter Again"
        
        try:
            key_ECC = create_ECC_keys(bits)
            p = int(key_ECC["public_key"]["p"])
            a = int(key_ECC["public_key"]["a"])
            b = int(key_ECC["public_key"]["b"])
            n = int(key_ECC["public_details"]["number_of_points"])
            key_ECDSA = create_ECDSA_keys(p, a, b, n)
            return key_ECDSA
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_ecdsa_sign_input(message, p, q, a, b, G, d):
        """Validate input for ECDSA signing"""
        if message is None or message == "":
            return False, "Enter Again"
        
        if p is None or q is None or a is None or G is None or d is None:
            return False, "Enter Again"
        
        try:
            p = int(p)
            q = int(q)
            a = int(a)
            d = int(d)
            Gx, Gy = G
        except (ValueError, TypeError):
            return False, "Invalid input format"
        
        if p == 0 or q == 0 or a == 0 or G == (0, 0) or d == 0:
            return False, "Enter Again"
        
        if not miller_rabin_test(p, 1000):
            return False, "p or q is not prime"
        
        if not miller_rabin_test(q, 1000):
            return False, "p or q is not prime"
        
        if not is_point_on_curve(G, a, p):
            return False, "G is not on the curve"
        
        return True, None
    
    @staticmethod
    def sign_with_ecdsa(message, p, q, a, b, G, d):
        """Sign message using ECDSA"""
        is_valid, error = SignatureService.validate_ecdsa_sign_input(message, p, q, a, b, G, d)
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            signed_message, hash_message = sign_ECDSA(message, {"p": p, "q": q, "a": a, "G": G}, d)
            return {"Signed Message": str(signed_message), "Hashed Message": str(hash_message)}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_ecdsa_verify_input(hash_message_str, signed_message_str, p, q, a, b, G, Q):
        """Validate input for ECDSA verification"""
        if hash_message_str is None or hash_message_str == "":
            return False, "Enter Again"
        
        if signed_message_str is None or signed_message_str == "":
            return False, "Enter Again"
        
        if p is None or q is None or a is None or b is None or G is None or Q is None:
            return False, "Enter Again"
        
        try:
            p = int(p)
            q = int(q)
            a = int(a)
            b = int(b)
            Gx, Gy = G
            Qx, Qy = Q
        except (ValueError, TypeError):
            return False, "Invalid input format"
        
        if p == 0 or q == 0 or a == 0 or b == 0 or G == (0, 0) or Q == (0, 0):
            return False, "Enter Again"
        
        if not miller_rabin_test(p, 1000):
            return False, "p or q is not prime"
        
        if not miller_rabin_test(q, 1000):
            return False, "p or q is not prime"
        
        if not is_point_on_curve(G, a, p):
            return False, "G is not on the curve"
        
        if not is_point_on_curve(Q, a, p):
            return False, "Q is not on the curve"
        
        return True, None
    
    @staticmethod
    def verify_ecdsa_signature(hash_message_str, signed_message_str, p, q, a, b, G, Q):
        """Verify ECDSA signature"""
        is_valid, error = SignatureService.validate_ecdsa_verify_input(
            hash_message_str, signed_message_str, p, q, a, b, G, Q
        )
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            # Parse arrays
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            
            signed_message_str = signed_message_str.strip("[]")
            signed_message_str_list = signed_message_str.replace("(", "").replace(")", "").split("),(")
            signed_message_tmp = [int(sub_str) for sub_str in signed_message_str_list[0].split(",")]
            signed_message = []
            for i in range(0, len(signed_message_tmp) - 1, 2):
                signed_message.append((signed_message_tmp[i], signed_message_tmp[i + 1]))
            
            result = verify_ECDSA(hash_message, signed_message, {"p": p, "q": q, "a": a, "b": b, "G": G, "Q": Q})
            return {"Verification: ": str(result)}
        except Exception as e:
            return {"Error": str(e)}
