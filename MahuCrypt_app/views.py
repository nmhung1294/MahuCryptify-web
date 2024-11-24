from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from MahuCrypt_app.cryptography.public_key_cryptography import *
from MahuCrypt_app.cryptography.classical_cryptography import *
from MahuCrypt_app.cryptography.signature import *
from MahuCrypt_app.model_mongo import UserModel
from MahuCrypt_app.cryptography.algos import *

class HandleSubmitCryptoSystem(APIView):
    @api_view(['POST'])
    def gen_RSA_key(request):
        try:
            data = request.data
            if (data is None): 
                return Response({"Error": "NULL Value - Please enter bits"})
            bits = int(data['bits'])
            if bits <= 1:
                return Response({"Error": "Bits must be greater than 0"})
            key_RSA = create_RSA_keys(bits)
            return Response(key_RSA)
        except Exception as e:
            return Response({"Error" : str(request.data)}) 
    
    @api_view(['POST'])
    def encrypt_RSA(request):
        try:
            data = request.data
            message = data['message']
            n = int(data['n'])
            e = int(data['e'])
            if (n < 0 or e < 0 or n == 0 or e == 0 or message == "" or message == None or e > n): 
                return Response({"Error": "NULL Value"})
            encrypted_message = EN_RSA(message, (n, e))
            return Response(encrypted_message)
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def decrypt_RSA(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            d = int(data['d'])
            p = int(data['p'])
            q = int(data['q'])
            if (encrypted_message == "" or encrypted_message == None or d == 0 or p == 0 or q == 0): 
                return Response({"Error": "NULL Value"})
            if d > p*q:
                return Response({"Error": "Invalid d"})
            if (miller_rabin_test(p, 1000) == False or miller_rabin_test(q, 1000) == False):
                return Response({"Error": "p or q is not prime"})
            decrypted_message = DE_RSA(encrypted_message, {"p": p, "q": q, "d": d})
            return Response(decrypted_message)
        except Exception as e:
            return Response({"Error" : str(e)})
        
    @api_view(['POST'])
    def gen_ElGamal_key(request):
        try:
            data = request.data
            bits = int(data['bits'])
            if bits <= 1:
                return Response({"Error": "Bits must be greater than 0"})
            key_ElGamal = create_ELGAMAL_keys(bits)
            return Response(key_ElGamal)
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def encrypt_ElGamal(request):
        data = request.data
        message = data['message']
        p = int(data['p'])
        alpha = int(data['alpha'])
        beta = int(data['beta'])
        if (p < 0 or alpha < 0 or beta < 0 or p == 0 or alpha == 0 or beta == 0 or message == "" or message == None): 
            return Response({"Error": "NULL Value"})
        if (miller_rabin_test(p, 1000) == False):
            return Response({"Error": "p is not prime"})
        if (is_primitive_root(alpha, p) == False):
            return Response({"Error": "alpha is not primitive root"})
        encrypted_message = EN_ELGAMAL(message, {"p": p, "alpha": alpha, "beta": beta})
        return Response(encrypted_message)
    
    @api_view(['POST'])
    def decrypt_ElGamal(request):
        data = request.data
        encrypted_message = data['encrypted_message']
        p = int(data['p'])
        a = int(data['a'])
        if (encrypted_message == "" or encrypted_message == None or p == 0 or a == 0): 
            return Response("Enter Again")
        if (miller_rabin_test(p, 1000) == False):
            return Response({"Error": "p is not prime"})
        decrypted_message = DE_ELGAMAL(encrypted_message, p, a)
        return Response(decrypted_message)
    
    @api_view(['POST'])
    def gen_ECC_key(request):
        try:
            data = request.data
            bits = int(data['bits'])
            if bits <= 1:
                return Response({"Error": "Bits must be greater than 0"})
            key_ECC = create_ECC_keys(bits)
            return Response(key_ECC)
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def encrypt_Elliptic_curve(request):
        try:
            data = request.data
            message = data['message']
            a = int(data['a'])
            p = int(data['p'])
            P = (int(data['Px']), int(data['Py']))
            B = (int(data['Bx']), int(data['By']))
            if (a == 0 or p == 0 or P == (0, 0) or B == (0, 0) or message == "" or message == None): 
                return Response({"Error": "NULL Value"})
            if (miller_rabin_test(p, 1000) == False):
                return Response({"Error": "p is not prime"})
            # if (is_point_on_curve(P, a, b, p) == False):
            #     return Response({"Error": "P is not on the curve"})
            # if (is_point_on_curve(B, a, b, p) == False):
            #     return Response({"Error": "B is not on the curve"})
            result = EN_ECC(message, {"a": a, "p" : p, "P" : P, "B": B})
            return Response(result)
        except Exception as e:
            return Response({"Error" : str(e)})
        
    @api_view(['POST'])
    def decrypt_Elliptic_curve(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            s = int(data['decryptionKey'])
            a = int(data['a'])
            p = int(data['p'])
            if (encrypted_message == "" or encrypted_message == None or a == 0 or p == 0 or s == 0): 
                return Response({"Error": "NULL Value"})
            if (miller_rabin_test(p, 1000) == False):
                return Response({"Error": "p is not prime"})
            result = DE_ECC(encrypted_message, {"a": a, "p" : p}, s)
            return Response(result)
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def encrypt_shift_cipher(request):
        try:
            data = request.data
            message = data['message']
            key = int(data['key'])
            encrypted_message = En_Shift_Cipher(message, key)
            return Response({"Encrypted Message" : encrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def decrypt_shift_cipher(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            key = int(data['key'])
            decrypted_message = De_Shift_Cipher(encrypted_message, key)
            return Response({"Decrypted Message" : decrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})
    
    @api_view(['POST'])
    def encrypt_vigenere_cipher(request):
        try:
            data = request.data
            message = data['message']
            key = data['key']
            encrypted_message = En_Vigenere_Cipher(message, key)
            return Response({"" : encrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})
    
    @api_view(['POST'])
    def decrypt_vigenere_cipher(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            key = data['key_decrypt']
            decrypted_message = De_Vigenere_Cipher(encrypted_message, key)
            return Response(decrypted_message)
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def encrypt_hill_cipher(request):
        try:
            data = request.data
            message = data['message']
            key = data['key']
            encrypted_message = En_Hill_Cipher(message, key)
            return Response({"Encrypted Message" : encrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})


    @api_view(['POST'])
    def decrypt_hill_cipher(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            key = data['key']
            decrypted_message = De_Hill_Cipher(encrypted_message, key)
            return Response({"Decrypted Message" : decrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def encrypt_affine_cipher(request):
        try:
            data = request.data
            message = data['message']
            a = int(data['a-af'])
            b = int(data['b-af'])
            if (a == 0 or b == 0 or message == "" or message == None): 
                return Response({"Error": "Enter Again"})
            encrypted_message = En_Affine_Cipher(message, a, b)
            return Response(encrypted_message) 
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def decrypt_affine_cipher(request):
        try:
            data = request.data
            encrypted_message = data['encrypted_message']
            a = int(data['a-af'])
            b = int(data['b-af'])
            if (a == 0 or b == 0 or encrypted_message == "" or encrypted_message == None): 
                return Response({"Error": "Enter Again"})
            decrypted_message = De_Affine_Cipher(encrypted_message, a, b)
            return Response({"Decrypted Message" : decrypted_message})
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def create_key_sign_RSA(request):
        try:
            data = request.data
            bits = int(data['bits'])
            if bits <= 1:
                return Response({"Error": "Bits must be greater than 0"})
            key_RSA = create_RSA_keys(bits)
            return Response(key_RSA)
        except Exception as e:
            return Response({"Error": str(e)})
    
    @api_view(['POST'])
    def sign_RSA(request):
        try:
            data = request.data
            message = data['message']
            p = int(data['p'])
            q = int(data['q'])
            d = int(data['d'])
            if (p == 0 or q == 0 or d == 0 or message == "" or message == None or d > p*q): 
                return Response("Enter Again")
            if (miller_rabin_test(p, 1000) == False or miller_rabin_test(q, 1000) == False):
                return Response("p or q is not prime")
            signed_message, hash_message = sign_RSA(message, {"p": p, "q": q, "d": d})
            return Response({"Signed Message": str(signed_message), "Hashed Message": str(hash_message)})
        except Exception as e:
            return Response({"Error": str(e)})

    @api_view(['POST'])
    def verify_RSA(request):
        try:
            data = request.data
            hash_message_str = data['hash_message']
            signed_message_str = data['signed']
            signed_message_str = signed_message_str.strip("[]")
            signed_message = [int(sub_str) for sub_str in signed_message_str.split(",")]
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            n = int(data['n'])
            e = int(data['e'])
            if (n == 0 or e == 0 or hash_message_str == "" or hash_message_str == None or e > n): 
                return Response("Enter Again")
            result = verify_RSA(hash_message, signed_message, (n, e))
            return Response({"Verification: ": str(result)})
        except Exception as e:
            return Response(str(e))
    
    @api_view(['POST'])
    def create_key_sign_ElGamal(request):
        try:
            data = request.data
            bits = int(data['bits'])
            if bits <= 1:
                return Response({"Error": "Bits must be greater than 0"})
            key_ElGamal = create_ELGAMAL_keys(bits)
            return Response(key_ElGamal)
        except Exception as e:
            return Response(str(e))
    
    @api_view(['POST'])
    def sign_ElGamal(request):
        try:
            data = request.data
            message = data['message']
            p = int(data['p'])
            alpha = int(data['alpha'])
            a = int(data['a'])
            if (p == 0 or alpha == 0 or a == 0 or message == "" or message == None): 
                return Response({"Error": "NULL Value"})
            if (miller_rabin_test(p, 1000) == False):
                return Response({"Error": "p is not prime"})
            if (is_primitive_root(alpha, p) == False):
                return Response({"Error": "alpha is not primitive root"})
            signed_message, hash_message = sign_ELGAMAL(message, {"p": p, "alpha": alpha}, a)
            return Response({"Signed Message" : str(signed_message), "Hashed Message": str(hash_message)})
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def verify_ElGamal(request):
        try:
            data = request.data
            hash_message_str = data['hash_message']
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            signed_message_str = data['signed']
            signed_message_str = signed_message_str.strip("[]")
            signed_message_str_list = signed_message_str.replace("(", "").replace(")", "").split("),(")
            signed_message_tmp = [int(sub_str) for sub_str in signed_message_str_list[0].split(",")]
            signed_message = []
            for i in range(0, len(signed_message_tmp) - 1, 2):
                signed_message.append((signed_message_tmp[i], signed_message_tmp[i + 1]))
            p = int(data['p'])
            alpha = int(data['alpha'])
            beta = int(data['beta'])
            if (p == 0 or alpha == 0 or beta == 0 or hash_message_str == "" or hash_message_str == None): 
                return Response({"Error": "NULL Value"})
            if (miller_rabin_test(p, 1000) == False):
                return Response({"Error": "p is not prime"})
            if (is_primitive_root(alpha, p) == False):
                return Response({"Error": "alpha is not primitive root"})
            result = verify_ELGAMAL(hash_message, signed_message, {"p": p, "alpha": alpha, "beta": beta})
            return Response({"Verification: ": str(result)})
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def create_key_sign_ECDSA(request):
        try:
            data = request.data
            bits = int(data['bits'])
            if bits <= 1:
                return Response("Enter Again")
            key_ECC = create_ECC_keys(bits)
            p = int(key_ECC["public_key"]["p"])
            a = int(key_ECC["public_key"]["a"])
            b = int(key_ECC["public_key"]["b"])
            n = int(key_ECC["public_details"]["number_of_points"]) 
            key_ECDSA = create_ECDSA_keys(p, a, b, n)
            return Response(key_ECDSA)
        except Exception as e:
            return Response(str(e))
    @api_view(['POST'])
    def sign_ECDSA(request):
        try:
            data = request.data
            message = data['message']
            p = int(data['p'])
            q = int(data['q'])
            a = int(data['a'])
            b = int(data['b'])
            G = (int(data['Gx']), int(data['Gy']))
            d = int(data['d'])
            if (p == 0 or q == 0 or a == 0 or G == (0, 0) or d == 0 or message == "" or message == None): 
                return Response("Enter Again")
            if (miller_rabin_test(p, 1000) == False or miller_rabin_test(q, 1000) == False):
                return Response({"Error": "p or q is not prime"})
            if (is_point_on_curve(G, a, p) == False):
                return Response({"Error": "G is not on the curve"})
            signed_message, hash_message = sign_ECDSA(message, {"p": p, "q": q, "a": a, "G": G}, d)
            return Response({"Signed Message" : str(signed_message), "Hashed Message": str(hash_message)})
        except Exception as e:
            return Response(str(e))

    @api_view(['POST'])
    def verify_ECDSA(request):
        try:
            data = request.data
            hash_message_str = data['hash_message']
            hash_message_str = hash_message_str.strip("[]")
            hash_message = [int(sub_str) for sub_str in hash_message_str.split(",")]
            signed_message_str = data['signed']
            signed_message_str = signed_message_str.strip("[]")
            signed_message_str_list = signed_message_str.replace("(", "").replace(")", "").split("),(")
            signed_message_tmp = [int(sub_str) for sub_str in signed_message_str_list[0].split(",")]
            signed_message = []
            for i in range(0, len(signed_message_tmp) - 1, 2):
                signed_message.append((signed_message_tmp[i], signed_message_tmp[i + 1]))
            p = int(data['p'])
            q = int(data['q'])
            a = int(data['a'])
            b = int(data['b'])
            G = (int(data['Gx']), int(data['Gy']))
            Q = (int(data['Qx']), int(data['Qy']))
            if (p == 0 or q == 0 or a == 0 or b == 0 or G == (0, 0) or Q == (0, 0) or hash_message_str == "" or hash_message_str == None): 
                return Response("Enter Again")
            if (miller_rabin_test(p, 1000) == False or miller_rabin_test(q, 1000) == False):
                return Response({"Error": "p or q is not prime"})
            if (is_point_on_curve(G, a, p) == False):
                return Response({"Error": "G is not on the curve"})
            if (is_point_on_curve(Q, a, p) == False):
                return Response({"Error": "Q is not on the curve"})
            result = verify_ECDSA(hash_message, signed_message, {"p": p, "q": q, "a": a, "b": b, "G": G, "Q": Q})
            return Response({"Verification: ": str(result)})
        except Exception as e:
            return Response({"Error" : str(e)})

    @api_view(['POST'])
    def prime_check(request):
        try:
            data = request.data
            n = int(data['num'])
            if n < 0:
                return Response("Enter Again")
            result = is_prime_aks(n)
            if result == True:
                return Response({"": f"{n} - Prime"})
            return Response({"": f"{n} - Composite"})
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def gcd(request):
        try:   
            data = request.data
            a = int(data['a'])
            b = int(data['b'])
            if a < 0 or b < 0:
                return Response({"Error": "Invalid input"})
            result = Ext_Euclide(a, b)[0]
            return Response({"Result" : str(result)})
        except Exception as e:
            return Response({"Error" : str(e)})
        
    @api_view(['POST'])
    def modular_exponentiation(request):
        try:
            data = request.data
            b = int(data['a'])
            n = int(data['b'])
            m = int(data['m'])
            if b < 0 or n < 0 or m < 0:
                return Response({"Error": "Invalid input"})
            result = modular_exponentiation(b, n, m)
            return Response({"Result" : str(result)})
        except Exception as e:
            return Response({"Error" : str(e)})
    
    @api_view(['POST'])
    def extended_euclidean_algorithm(request):
        try:
            data = request.data
            a = int(data['a'])
            m = int(data['m'])
            if a < 0 or m < 0:
                return Response({"Error": "Invalid input"})
            result = Ext_Euclide(a, m)
            if result[0] != 1:
                return Response({"Result": "No modular multiplicative inverse"})
            invmod = result[1]
            if result[1] < 0: 
                invmod = m + result[1]
            return Response({"Result": invmod})
        except Exception as e:
            return Response({"Error" : str(e)})

    @api_view(['GET'])
    def test(request):
        user_data = UserModel.get_blog_by_id('67370eaab590cec3ccf1423d')
        return Response(user_data)
    @api_view(['GET'])
    def get_all_blogs(request):
        blogs = UserModel.get_all_collection('blog')
        blogs_list = [{"_id": str(blog["_id"]), "title": blog["title"], "content": blog["content"]} for blog in blogs]
        return Response(blogs_list)
    
    @api_view(['GET'])
    def get_all_crypto_systems(request):
        crypto_system = UserModel.get_all_collection('crypto_system')
        # Convert ObjectId to string for JSON serialization
        crypto_system_list = [
            {
                "_id": str(crypto["_id"]),  # Giữ nguyên
                "title": crypto["title"],    # Giữ nguyên
                "fields": {                  # Cập nhật để lấy các trường cho từng loại form
                    "create_key": crypto["fields"]["create_key"],
                    "encrypt": crypto["fields"]["encrypt"],
                    "decrypt": crypto["fields"]["decrypt"]
                },
                "encrypt": crypto["encrypt"], # Giữ nguyên nếu cần thiết
                "decrypt": crypto["decrypt"]  # Giữ nguyên nếu cần thiết
            } for crypto in crypto_system
        ]
        return Response(crypto_system_list)
    
    @api_view(['GET'])
    def get_all_digital_signature(request):
        digital_signature = UserModel.get_all_collection('digital_signature')
        digital_signature_list = [
            {
                "_id": str(digital["_id"]), 
                "title": digital["title"],  
                "fields": {                  
                    "create_key": digital["fields"]["create_key"],
                    "sign": digital["fields"]["sign"],
                    "verify": digital["fields"]["verify"]
                }
            } for digital in digital_signature
        ]
        return Response(digital_signature_list)
    
    @api_view(['GET'])
    def get_all_algorithm(request):
        algorithm = UserModel.get_all_collection('algorithm')
        algorithm_list = [
            {
                "_id": str(algo["_id"]), 
                "title": algo["title"],  
                "fields": {                  
                    "input": algo["fields"]["input"],
                }
            } for algo in algorithm
        ]
        return Response(algorithm_list)
