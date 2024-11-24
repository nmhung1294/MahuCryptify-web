from MahuCrypt_app.cryptography.algos import *
from MahuCrypt_app.cryptography.pre_process import *
import secrets
#from numpy import *

def sign_RSA(string, private_key):
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    d = private_key["d"]
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_base10 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    signed_x_RSA = []
    for sub_str in sub_str_base10:
        signed_x_RSA.append(modular_exponentiation(sub_str, d, n))
    return signed_x_RSA, sub_str_base10

def verify_RSA(hash_message, signed, public_key):
    n, e = public_key
    for i, x in enumerate(hash_message):
        if modular_exponentiation(signed[i], e, n) != x:
            return False
    return True



def sign_ELGAMAL(string, public_key, private_key):
    p, alpha = public_key["p"], public_key["alpha"]
    a = private_key
    k = secrets.randbelow(p - 1) + 1
    while True:
        if (k > p - 1 or k < 1 or Ext_Euclide(k, p - 1)[0] != 1):
            k = secrets.randbelow(p - 1) + 1
        else:
            break
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_base10 = [convert_str_to_int(sub_string) for sub_string in sub_strings]
    sign_x_Elgamal = []
    for i in range(len(sub_str_base10)):
        gamma = modular_exponentiation(alpha, k, p)
        delta = (sub_str_base10[i] - a * gamma) * Ext_Euclide(k, p - 1)[1] % (p - 1)
        sign_x_Elgamal.append((gamma, delta))
    return sign_x_Elgamal, sub_str_base10

def verify_ELGAMAL(hash_message, sign_x_Elgamal, public_key):
    alpha, beta, p = public_key["alpha"], public_key["beta"], public_key["p"]
    for i, x in enumerate(hash_message):
        gamma, delta = sign_x_Elgamal[i]
        y1 = (modular_exponentiation(beta, gamma, p) * modular_exponentiation(gamma,delta, p)) % p
        y2 = (modular_exponentiation(alpha, x, p)) % p
        if y1 != y2:
            return False
    return True


def sign_ECDSA(string, public_key, private_key):
    p,q, a, G = public_key["p"], public_key["q"], public_key["a"], public_key["G"]
    d = private_key
    #Sign the message
    sub_strings = sub_string(pre_solve(string), 4)
    sub_str_base10 = [convert_str_to_int(sub_string) for sub_string in sub_strings]

    check = False #Find r
    while (check != True):
        k = random.randint(1, q - 1)
        kG = double_and_add(G, k, a, p)
        r = kG[0] % q
        if (r != 0):
            check = True

    signed_x_ECDSA = []
    for x in sub_str_base10:
        check = False
        while (check != True):
            k = random.randint(1, q - 1)
            kG_H = double_and_add(G, k, a, p)
            r = kG_H[0] % q
            s = (Ext_Euclide(k, q)[1] * (x + d*r)) % q
            if (s != 0 and r != 0):
                check = True
                signed_x_ECDSA.append((r, s))
    return str(signed_x_ECDSA), str(sub_str_base10)

def verify_ECDSA(hash_message, signed_x, public_sign_key):
    p, q, a, b, G, Q = public_sign_key["p"], public_sign_key["q"], public_sign_key["a"], public_sign_key["b"], public_sign_key["G"], public_sign_key["Q"]
    for i, x in enumerate(hash_message):
        r, s = signed_x[i]
        w = Ext_Euclide(s, q)[1] % q
        u1 = (x * w) % q
        u2 = (r * w) % q
        u1G = double_and_add(G, u1, a, p)
        u2Q = double_and_add(Q, u2, a, p)
        X = add_points(u1G, u2Q, a, p)
        
        if X[0] % q != r:
            return False
    return True