from MahuCrypt_app.cryptography.algos import *
from pre_process import *
from numpy import *

def EN_RSA(string, p, q):
    """
    Encrypts the string using the RSA algorithm
    """
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 2
    d = Ext_Euclide(e, phi_n)[1] % phi_n
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_bas26 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    encrypted = []
    for sub_str in sub_str_bas26:
        encrypted.append(modular_exponentiation(sub_str, e, n))
    return {"public_key": (n, e), "private_key": {"d": d, "p": p, "q": q}, "encrypted": encrypted}

def DE_RSA(encrypted, private_key):
    """
    Decrypts the string using the RSA algorithm
    """
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    d = private_key["d"]
    decrypted = []
    for sub_str in encrypted:
        decrypted.append(modular_exponentiation(sub_str, d, n))
    decrypted_str = "".join([convert_int_to_str(sub_str) for sub_str in decrypted])
    return decrypted_str

def EN_ELGAMAL(string, p, a, k):
    """
    Encrypts the string using the El Gamal algorithm
    """
    alpha = 2
    beta = modular_exponentiation(alpha, a, p)
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_base26 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    encrypted = []
    for sub_str in sub_str_base26:
        y1 = modular_exponentiation(alpha, k, p)
        y2 = (sub_str * modular_exponentiation(beta, k, p)) % p
        encrypted.append((y1, y2))
    return {"public_key": (p, alpha, beta), "private_key": a, "encrypted": encrypted}

def DE_ELGAMAL(encrypted, private_key):
    """
    Decrypts the string using the El Gamal algorithm
    """
    p = encrypted["public_key"][0]
    a = private_key
    decrypted = []
    for y1, y2 in encrypted["encrypted"]:
        sub_str = (y2 * modular_exponentiation(y1, p - 1 - a, p)) % p
        decrypted.append(sub_str)
    decrypted_str = "".join([convert_int_to_str(sub_str) for sub_str in decrypted])
    return decrypted_str

def EN_EC(string, p, s, k, P):
    """
    Encrypts the string using the Elliptic Curve algorithm
    """
    encrypted = []
    sub_strings = sub_string(pre_solve(string), 4)
    sub_string_int = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    B = double_and_add(P, s, p)
    
    return encrypted

#add more functions here