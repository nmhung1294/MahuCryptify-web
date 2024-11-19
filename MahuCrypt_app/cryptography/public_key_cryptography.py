from MahuCrypt_app.cryptography.algos import *
from MahuCrypt_app.cryptography.pre_process import *
from numpy import *
import secrets
import re

def get_prime_number(bits):
    while True:
        p = secrets.randbits(bits)
        if p >= 2**(bits - 1) and p < 2**bits and miller_rabin_test(p, 10000):
            return p

#Create RSA keys

def create_RSA_keys(bits):
    p = get_prime_number(bits)
    q = get_prime_number(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = get_prime_number(bits - 1)
    d = Ext_Euclide(e, phi_n)[1] % phi_n
    return {"public_key": { "n" : str(n), "e": str(e)}, "private_key": {"d": str(d), "p": str(p), "q": str(q)}}

#Create El Gamal keys

def create_ELGAMAL_keys(bits):
    p = get_prime_number(bits)
    alpha = 2
    a = secrets.randbelow(p - 1) + 1
    beta = modular_exponentiation(alpha, a, p)
    return {"public_key": {"p": str(p), "alpha" : str(alpha), "beta": str(beta)}, "private_key - a": str(a)}

#Create ECC keys
def create_ECC_keys(bits):
    p = get_prime_number(bits)
    while True:
        a = secrets.randbelow(20 - 1) + 1
        b = secrets.randbelow(20 - 1) + 1
        if 4*a**3 + 27*b**2 != 0:
            break
    l = 0
    #points_on_curve=[]
    quadratic_residue = find_quadratic_residue(p)
    for x in range(0, p):
        y_pow_2 = (x**3 + a*x + b) % p
        if (y_pow_2 == 0):
            #oints_on_curve.append((x,0))
            l += 1
        if (str(y_pow_2) in quadratic_residue):
            #y_1, y_2 = quadratic_residue[str(y_pow_2)]
            #points_on_curve.append((x,y_1))
            #points_on_curve.append((x,y_2))
            l += 2
    l += 1
    P = find_point_on_curve(p, a, b)
    s = secrets.randbelow(p - 1) + 1
    B = double_and_add(P, s, a, p)
    return {"public_key": {"p": str(p), "a": str(a), "b": str(b), "P": str(P), "B":str(B)}, "private_key": str(s), "public_details": {"number_of_points": str(l)}}

def create_ECDSA_keys(p, a, b, n):
    q = largest_prime_factor(n)
    h = n // q
    P = find_point_on_curve(p, a, b)
    G = double_and_add(P, h, a, p)
    d = secrets.randbelow(q - 1) + 1
    Q = double_and_add(G, d, a, p)
    return {"public_key": {"p": str(p), "q": str(q), "a": str(a), "b": str(b), "G": str(G), "Q": str(Q)}, "private_key": str(d)}

#Encrypt message using RSA system

def EN_RSA(string, public_key):
    """
    Encrypts the string using the RSA algorithm
    """
    n, e = public_key
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_bas26 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    encrypted = []
    for sub_str in sub_str_bas26:
        encrypted.append(modular_exponentiation(sub_str, e, n))
    return str(encrypted)

#Decrypt message using RSA system

def DE_RSA(encrypted, private_key):
    """
    Decrypts the string using the RSA algorithm
    """
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    d = private_key["d"]
    decrypted = []
    encrypted = encrypted.strip("[]")
    encrypted_message = [int(sub_str) for sub_str in encrypted.split(",")]
    for sub_str in encrypted_message:
        decrypted.append(modular_exponentiation(sub_str, d, n))
    decrypted_str = "".join([convert_int_to_str(sub_str) for sub_str in decrypted])
    return {"Decrypted": decrypted_str}

#Encrypt message using El Gamal system

def EN_ELGAMAL(string, public_key):
    """
    Encrypts the string using the El Gamal algorithm
    """
    p, alpha, beta = public_key["p"], public_key["alpha"], public_key["beta"]
    k = secrets.randbelow(p // 10 - 1) + 1
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_base10 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    encrypted = []
    for sub_str in sub_str_base10:
        y1 = modular_exponentiation(alpha, k, p)
        y2 = (sub_str * modular_exponentiation(beta, k, p)) % p
        encrypted.append((y1, y2))
    return {"Encrypted": encrypted}

#Decrypt message using El Gamal system

def DE_ELGAMAL(encrypted_message_str, p , private_key):
    """
    Decrypts the string using the El Gamal algorithm
    """
    a = private_key
    decrypted = []
    encrypted_message_str = encrypted_message_str.strip("[]")
    if "(" in encrypted_message_str and ")" in encrypted_message_str:
        encrypted_message_str_list = encrypted_message_str.replace("(", "").replace(")", "").split("),(")
    else:
        encrypted_message_str_list = encrypted_message_str.split("],[")
    encrypted_message_tmp = [int(num) for sub_str in encrypted_message_str_list for num in sub_str.split(",")]
    encrypted = []
    for i in range(0, len(encrypted_message_tmp) - 1, 2):
        encrypted.append((encrypted_message_tmp[i], encrypted_message_tmp[i + 1]))
    for y1, y2 in encrypted:
        sub_str = (y2 * modular_exponentiation(y1, p - 1 - a, p)) % p
        decrypted.append(sub_str)
    decrypted_str = "".join([convert_int_to_str(sub_str) for sub_str in decrypted])
    return {"Decrypted": decrypted_str}

#Encrypt message using Elliptic Curve system

def EN_ECC(string, public_key):
    """
    Encrypts the string using the Elliptic Curve algorithm
    """
    a, p, P, B = public_key["a"], public_key["p"], public_key["P"], public_key["B"]
    k = secrets.randbelow(p//10 - 1) + 1
    encrypted = []
    sub_strings = sub_string(pre_solve(string), 3)
    sub_string_int = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    message_points = [double_and_add(P, sub_str_int, a, p ) for sub_str_int in sub_string_int]
    for point in message_points:
        C1 = double_and_add(P, k, a, p)
        M = double_and_add(B, k, a, p)
        C2 = add_points(point, M, a, p)
        encrypted.append((C1, C2))
    return message_points, encrypted

#Decrypt message using Elliptic Curve system
def DE_ECC(encrypted_message_str, public_key, private_key):
    a, p = public_key["a"], public_key["p"]
    s = private_key
    str_list = re.findall(r'\d+', encrypted_message_str)
    int_list = [int(num) for num in str_list]
    encrypted_message = []
    for i in range(0, len(int_list) - 1, 4):
        encrypted_message.append(((int_list[i], int_list[i + 1]), (int_list[i + 2], int_list[i + 3])))
    decrypted_points = []
    for en in encrypted_message:
        C1, C2 = en
        sC1 = double_and_add(C1, s, a, p)
        tmp = (sC1[0], -sC1[1])
        decrypted_point = add_points(C2, tmp, a, p)
        decrypted_points.append(decrypted_point)
    return {"Decrypted": str(decrypted_points)}
