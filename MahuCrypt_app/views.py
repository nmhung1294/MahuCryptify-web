from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from MahuCrypt_app.cryptography.public_key_cryptography import *
from MahuCrypt_app.model_mongo import UserModel

class HandleSubmitCryptoSystem(APIView):
    @api_view(['POST'])
    def gen_RSA_key(request):
        data = request.data
        bits = int(data['bits'])
        key_RSA = create_RSA_keys(bits)
        return Response(key_RSA)
    
    @api_view(['POST'])
    def encrypt_RSA(request):
        data = request.data
        message = data['message']
        n = int(data['n'])
        e = int(data['e'])
        if (n < 0 or e < 0 or n == 0 or e == 0 or message == "" or message == None or e > n): 
            return Response("Enter Again")
        encrypted_message = EN_RSA(message, (n, e))
        return Response(encrypted_message)
    
    @api_view(['POST'])
    def decrypt_RSA(request):
        data = request.data
        encrypted_message = data['encrypted_message']
        d = int(data['d'])
        p = int(data['p'])
        q = int(data['q'])
        if (encrypted_message == "" or encrypted_message == None or d == 0 or p == 0 or q == 0): 
            return Response("Enter Again")
        decrypted_message = DE_RSA(encrypted_message, {"p": p, "q": q, "d": d})
        return Response(decrypted_message)
    @api_view(['POST'])
    def gen_ElGamal_key(request):
        data = request.data
        bits = int(data['bits'])
        key_ElGamal = create_ELGAMAL_keys(bits)
        return Response(key_ElGamal)
    
    @api_view(['POST'])
    def encrypt_ElGamal(request):
        data = request.data
        message = data['message']
        p = int(data['p'])
        alpha = int(data['alpha'])
        beta = int(data['beta'])
        if (p < 0 or alpha < 0 or beta < 0 or p == 0 or alpha == 0 or beta == 0 or message == "" or message == None): 
            return Response("Enter Again")
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
        decrypted_message = DE_ELGAMAL(encrypted_message, p, a)
        return Response(decrypted_message)
    
    @api_view(['POST'])
    def gen_ECC_key(request):
        data = request.data
        bits = int(data['bits'])
        key_ECC = create_ECC_keys(bits)
        return Response(key_ECC)
    
    @api_view(['POST'])
    def encrypt_Elliptic_curve(request):
        data = request.data
        message = data['message']
        a = int(data['a'])
        p = int(data['p'])
        P = (int(data['Px']), int(data['Py']))
        B = (int(data['Bx']), int(data['By']))
        result = EN_ECC(message, {"a": a, "p" : p, "P" : P, "B": B})
        return Response({"Message points: ": result[0], "Encrypted message: ": result[1]})
        
    @api_view(['POST'])
    def decrypt_Elliptic_curve(request):
        data = request.data
        encrypted_message = data['encrypted_message']
        s = int(data['decryptionKey'])
        a = int(data['a'])
        p = int(data['p'])
        result = DE_ECC(encrypted_message, {"a": a, "p" : p}, s)
        return Response(result)
    
    @api_view(['GET'])
    def test(request):
        user_data = UserModel.get_blog_by_id('67370eaab590cec3ccf1423d')
        return Response(user_data)
    @api_view(['GET'])
    def get_all_blog(request):
        blogs = UserModel.get_all_blogs()
        # Convert ObjectId to string for JSON serialization
        blogs_list = [{"_id": str(blog["_id"]), "title": blog["title"], "content": blog["content"]} for blog in blogs]
        return Response(blogs_list)