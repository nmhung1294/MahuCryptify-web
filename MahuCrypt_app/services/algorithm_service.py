"""
Algorithm Service - Business logic for mathematical algorithms
"""

from MahuCrypt_app.cryptography.algos import (
    is_prime_aks, Ext_Euclide, modular_exponentiation
)


class AlgorithmService:
    """Service class for algorithm operations"""
    
    @staticmethod
    def validate_prime_check_input(n):
        """Validate input for prime checking"""
        if n is None:
            return False, "Enter Again"
        
        try:
            n = int(n)
        except (ValueError, TypeError):
            return False, "Input must be an integer"
        
        if n < 0:
            return False, "Enter Again"
        
        return True, None
    
    @staticmethod
    def check_prime(n):
        """Check if number is prime using AKS"""
        is_valid, error = AlgorithmService.validate_prime_check_input(n)
        if not is_valid:
            return {"Error": error} if error != "Enter Again" else error
        
        try:
            result = is_prime_aks(n)
            if result:
                return {"": f"{n} - Prime"}
            return {"": f"{n} - Composite"}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_gcd_input(a, b):
        """Validate input for GCD"""
        if a is None or b is None:
            return False, "Invalid input"
        
        try:
            a = int(a)
            b = int(b)
        except (ValueError, TypeError):
            return False, "Invalid input"
        
        if a < 0 or b < 0:
            return False, "Invalid input"
        
        return True, None
    
    @staticmethod
    def calculate_gcd(a, b):
        """Calculate GCD using Extended Euclidean Algorithm"""
        is_valid, error = AlgorithmService.validate_gcd_input(a, b)
        if not is_valid:
            return {"Error": error}
        
        try:
            result = Ext_Euclide(a, b)[0]
            return {"Result": str(result)}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_modular_exp_input(a, b, m):
        """Validate input for modular exponentiation"""
        if a is None or b is None or m is None:
            return False, "Invalid input"
        
        try:
            a = int(a)
            b = int(b)
            m = int(m)
        except (ValueError, TypeError):
            return False, "Invalid input"
        
        if a < 0 or b < 0 or m < 0:
            return False, "Invalid input"
        
        return True, None
    
    @staticmethod
    def calculate_modular_exp(a, b, m):
        """Calculate a^b mod m"""
        is_valid, error = AlgorithmService.validate_modular_exp_input(a, b, m)
        if not is_valid:
            return {"Error": error}
        
        try:
            result = modular_exponentiation(a, b, m)
            return {"Result": str(result)}
        except Exception as e:
            return {"Error": str(e)}
    
    @staticmethod
    def validate_mod_inverse_input(a, m):
        """Validate input for modular inverse"""
        if a is None or m is None:
            return False, "Invalid input"
        
        try:
            a = int(a)
            m = int(m)
        except (ValueError, TypeError):
            return False, "Invalid input"
        
        if a < 0 or m < 0:
            return False, "Invalid input"
        
        return True, None
    
    @staticmethod
    def calculate_mod_inverse(a, m):
        """Calculate modular multiplicative inverse"""
        is_valid, error = AlgorithmService.validate_mod_inverse_input(a, m)
        if not is_valid:
            return {"Error": error}
        
        try:
            result = Ext_Euclide(a, m)
            if result[0] != 1:
                return {"Result": "No modular multiplicative inverse"}
            
            invmod = result[1]
            if result[1] < 0:
                invmod = m + result[1]
            return {"Result": invmod}
        except Exception as e:
            return {"Error": str(e)}
