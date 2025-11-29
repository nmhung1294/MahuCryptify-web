from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from MahuCrypt_app.model_mongo import UserModel
from MahuCrypt_app.services.rsa_service import RSAService
from MahuCrypt_app.services.elgamal_service import ElGamalService
from MahuCrypt_app.services.ecc_service import ECCService
from MahuCrypt_app.services.classical_service import ClassicalService
from MahuCrypt_app.services.signature_service import SignatureService
from MahuCrypt_app.services.algorithm_service import AlgorithmService

class HandleSubmitCryptoSystem(APIView):
    # RSA Operations
    @api_view(['POST'])
    def gen_RSA_key(request):
        bits = request.data.get('bits')
        result = RSAService.generate_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def encrypt_RSA(request):
        data = request.data
        message = data.get('message')
        n = data.get('n')
        e = data.get('e')
        result = RSAService.encrypt(message, n, e)
        return Response(result)
    
    @api_view(['POST'])
    def decrypt_RSA(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        p = data.get('p')
        q = data.get('q')
        d = data.get('d')
        result = RSAService.decrypt(encrypted_message, p, q, d)
        return Response(result)
        
    # ElGamal Operations
    @api_view(['POST'])
    def gen_ElGamal_key(request):
        bits = request.data.get('bits')
        result = ElGamalService.generate_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def encrypt_ElGamal(request):
        data = request.data
        message = data.get('message')
        p = data.get('p')
        alpha = data.get('alpha')
        beta = data.get('beta')
        result = ElGamalService.encrypt(message, p, alpha, beta)
        return Response(result)
    
    @api_view(['POST'])
    def decrypt_ElGamal(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        p = data.get('p')
        a = data.get('a')
        result = ElGamalService.decrypt(encrypted_message, p, a)
        return Response(result)
    
    # ECC Operations
    @api_view(['POST'])
    def gen_ECC_key(request):
        bits = request.data.get('bits')
        result = ECCService.generate_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def encrypt_Elliptic_curve(request):
        data = request.data
        message = data.get('message')
        a = data.get('a')
        p = data.get('p')
        P = (int(data.get('Px', 0)), int(data.get('Py', 0)))
        B = (int(data.get('Bx', 0)), int(data.get('By', 0)))
        result = ECCService.encrypt(message, a, p, P, B)
        return Response(result)
        
    @api_view(['POST'])
    def decrypt_Elliptic_curve(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        s = data.get('decryptionKey')
        a = data.get('a')
        p = data.get('p')
        result = ECCService.decrypt(encrypted_message, a, p, s)
        return Response(result)
    
    # Classical Ciphers
    @api_view(['POST'])
    def encrypt_shift_cipher(request):
        data = request.data
        message = data.get('message')
        key = data.get('key')
        result = ClassicalService.encrypt_shift(message, key)
        return Response(result)

    @api_view(['POST'])
    def decrypt_shift_cipher(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        key = data.get('key')
        result = ClassicalService.decrypt_shift(encrypted_message, key)
        return Response(result)
    
    @api_view(['POST'])
    def encrypt_vigenere_cipher(request):
        data = request.data
        message = data.get('message')
        key = data.get('key')
        result = ClassicalService.encrypt_vigenere(message, key)
        return Response(result)
    
    @api_view(['POST'])
    def decrypt_vigenere_cipher(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        key = data.get('key_decrypt')
        result = ClassicalService.decrypt_vigenere(encrypted_message, key)
        return Response(result)

    @api_view(['POST'])
    def encrypt_hill_cipher(request):
        data = request.data
        message = data.get('message')
        key = data.get('key')
        result = ClassicalService.encrypt_hill(message, key)
        return Response(result)

    @api_view(['POST'])
    def decrypt_hill_cipher(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        key = data.get('key')
        result = ClassicalService.decrypt_hill(encrypted_message, key)
        return Response(result)

    @api_view(['POST'])
    def encrypt_affine_cipher(request):
        data = request.data
        message = data.get('message')
        a = data.get('a-af')
        b = data.get('b-af')
        result = ClassicalService.encrypt_affine(message, a, b)
        return Response(result)

    @api_view(['POST'])
    def decrypt_affine_cipher(request):
        data = request.data
        encrypted_message = data.get('encrypted_message')
        a = data.get('a-af')
        b = data.get('b-af')
        result = ClassicalService.decrypt_affine(encrypted_message, a, b)
        return Response(result)

    # Digital Signatures - RSA
    @api_view(['POST'])
    def create_key_sign_RSA(request):
        bits = request.data.get('bits')
        result = RSAService.generate_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def sign_RSA(request):
        data = request.data
        message = data.get('message')
        p = data.get('p')
        q = data.get('q')
        d = data.get('d')
        result = SignatureService.sign_with_rsa(message, p, q, d)
        return Response(result)

    @api_view(['POST'])
    def verify_RSA(request):
        data = request.data
        hash_message_str = data.get('hash_message')
        signed_message_str = data.get('signed')
        n = data.get('n')
        e = data.get('e')
        result = SignatureService.verify_rsa_signature(hash_message_str, signed_message_str, n, e)
        return Response(result)
    
    # Digital Signatures - ElGamal
    @api_view(['POST'])
    def create_key_sign_ElGamal(request):
        bits = request.data.get('bits')
        result = ElGamalService.generate_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def sign_ElGamal(request):
        data = request.data
        message = data.get('message')
        p = data.get('p')
        alpha = data.get('alpha')
        a = data.get('a')
        result = SignatureService.sign_with_elgamal(message, p, alpha, a)
        return Response(result)
    
    @api_view(['POST'])
    def verify_ElGamal(request):
        data = request.data
        hash_message_str = data.get('hash_message')
        signed_message_str = data.get('signed')
        p = data.get('p')
        alpha = data.get('alpha')
        beta = data.get('beta')
        result = SignatureService.verify_elgamal_signature(
            hash_message_str, signed_message_str, p, alpha, beta
        )
        return Response(result)
    
    # Digital Signatures - ECDSA
    @api_view(['POST'])
    def create_key_sign_ECDSA(request):
        bits = request.data.get('bits')
        result = SignatureService.create_ecdsa_keys(bits)
        return Response(result)
    
    @api_view(['POST'])
    def sign_ECDSA(request):
        data = request.data
        message = data.get('message')
        p = data.get('p')
        q = data.get('q')
        a = data.get('a')
        b = data.get('b')
        G = (int(data.get('Gx', 0)), int(data.get('Gy', 0)))
        d = data.get('d')
        result = SignatureService.sign_with_ecdsa(message, p, q, a, b, G, d)
        return Response(result)

    @api_view(['POST'])
    def verify_ECDSA(request):
        data = request.data
        hash_message_str = data.get('hash_message')
        signed_message_str = data.get('signed')
        p = data.get('p')
        q = data.get('q')
        a = data.get('a')
        b = data.get('b')
        G = (int(data.get('Gx', 0)), int(data.get('Gy', 0)))
        Q = (int(data.get('Qx', 0)), int(data.get('Qy', 0)))
        result = SignatureService.verify_ecdsa_signature(
            hash_message_str, signed_message_str, p, q, a, b, G, Q
        )
        return Response(result)

    # Algorithm Operations
    @api_view(['POST'])
    def prime_check(request):
        n = request.data.get('num')
        result = AlgorithmService.check_prime(n)
        return Response(result)
    
    @api_view(['POST'])
    def gcd(request):
        data = request.data
        a = data.get('a')
        b = data.get('b')
        result = AlgorithmService.calculate_gcd(a, b)
        return Response(result)
        
    @api_view(['POST'])
    def modular_exponentiation(request):
        data = request.data
        a = data.get('a')
        b = data.get('b')
        m = data.get('m')
        result = AlgorithmService.calculate_modular_exp(a, b, m)
        return Response(result)
    
    @api_view(['POST'])
    def extended_euclidean_algorithm(request):
        data = request.data
        a = data.get('a')
        m = data.get('m')
        result = AlgorithmService.calculate_mod_inverse(a, m)
        return Response(result)

    # MongoDB Operations
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
        crypto_system_list = [
            {
                "_id": str(crypto["_id"]),
                "title": crypto["title"],
                "fields": {
                    "create_key": crypto["fields"]["create_key"],
                    "encrypt": crypto["fields"]["encrypt"],
                    "decrypt": crypto["fields"]["decrypt"]
                },
                "encrypt": crypto["encrypt"],
                "decrypt": crypto["decrypt"]
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

