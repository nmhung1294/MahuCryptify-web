from MahuCrypt_app.cryptography.algos import *
import numpy as np


def En_Shift_Cipher(string, shift):
    """
    Shifts the string by the shift value
    """
    shifted_string = ""
    for char in string:
        if char.isalpha():
            shifted_string += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            shifted_string += char
    return shifted_string

def De_Shift_Cipher(string, shift):
    """
    Shifts the string by the shift value
    """
    shifted_string = ""
    for char in string:
        if char.isalpha():
            shifted_string += chr((ord(char) - 65 - shift) % 26 + 65)
        else:
            shifted_string += char
    return shifted_string

def En_Affine_Cipher(string, a, b):
    """
    Encrypts the string using the affine cipher
    """
    encrypted_string = ""
    for char in string:
        if char.isalpha():
            encrypted_string += chr((a * (ord(char) - 65) + b) % 26 + 65)
        else:
            encrypted_string += char
    return encrypted_string

def De_Affine_Cipher(string, a, b):
    """
    Decrypts the string using the affine cipher
    """
    decrypted_string = ""
    for char in string:
        if char.isalpha():
            decrypted_string += chr(((ord(char) - 65 - b) * Ext_Euclide(a, 26)[1]) % 26 + 65)
        else:
            decrypted_string += char
    return decrypted_string

def En_Vigenere_Cipher(string, key):
    """
    Encrypts the string using the Vigenere cipher
    """
    encrypted_string = ""
    key_length = len(key)
    for i, char in enumerate(string):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - 65
            encrypted_string += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            encrypted_string += char
    return encrypted_string

def De_Vigenere_Cipher(string, key):
    """
    Decrypts the string using the Vigenere cipher
    """
    decrypted_string = ""
    key_length = len(key)
    for i, char in enumerate(string):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - 65
            decrypted_string += chr((ord(char) - 65 - shift) % 26 + 65)
        else:
            decrypted_string += char
    return decrypted_string

def En_Hill_Cipher(string, key):
    """
    Encrypts the string using the Hill cipher
    """
    encrypted_string = ""
    key = key.upper()
    key_length = len(key)
    key_matrix = [[ord(char) - 65 for char in key]]
    for i in range(1, key_length):
        key_matrix.append([(key_matrix[0][i] + i) % 26])
    key_matrix = np.array(key_matrix)
    string = string.upper()
    string_length = len(string)
    for i in range(0, string_length, key_length):
        block = [ord(char) - 65 for char in string[i:i + key_length]]
        block = np.array(block).reshape(-1, 1)
        encrypted_block = np.dot(key_matrix, block) % 26
        for char in encrypted_block:
            encrypted_string += chr(char[0] + 65)
    return encrypted_string

def De_Hill_Cipher(string, key):
    """
    Decrypts the string using the Hill cipher
    """
    decrypted_string = ""
    key = key.upper()
    key_length = len(key)
    key_matrix = [[ord(char) - 65 for char in key]]
    for i in range(1, key_length):
        key_matrix.append([(key_matrix[0][i] + i) % 26])
    key_matrix = np.array(key_matrix)
    key_matrix = np.linalg.inv(key_matrix)
    key_matrix = np.round(key_matrix * np.linalg.det(key_matrix) * Ext_Euclide(int(np.linalg.det(key_matrix)), 26)[1]) % 26
    string = string.upper()
    string_length = len(string)
    for i in range(0, string_length, key_length):
        block = [ord(char) - 65 for char in string[i:i + key_length]]
        block = np.array(block).reshape(-1, 1)
        decrypted_block = np.dot(key_matrix, block) % 26
        for char in decrypted_block:
            decrypted_string += chr(char[0] + 65)
    return decrypted_string
