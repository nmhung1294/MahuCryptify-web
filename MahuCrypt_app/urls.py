from django.urls import path
from MahuCrypt_app.views import HandleSubmitCryptoSystem
urlpatterns = [
    path('test/', HandleSubmitCryptoSystem.test, name='test'),
    path('blog/', HandleSubmitCryptoSystem.get_all_blogs, name='get_all_blogs'),
    path('cryptosystems/', HandleSubmitCryptoSystem.get_all_crypto_systems, name='get_all_crypto_systems'),
    path('digitalsignature/', HandleSubmitCryptoSystem.get_all_digital_signature, name='get_all_digital_signature'),
    path('algorithm/', HandleSubmitCryptoSystem.get_all_algorithm, name='get_all_algorithm'),
    
    path('cryptosystem/rsa/create_key/', HandleSubmitCryptoSystem.gen_RSA_key, name='gen_RSA_key'),
    path('cryptosystem/rsa/encrypt/', HandleSubmitCryptoSystem.encrypt_RSA, name='encrypt_RSA'),
    path('cryptosystem/rsa/decrypt/', HandleSubmitCryptoSystem.decrypt_RSA, name='decrypt_RSA'),
    # path('cryptosystem/rsa/sign/', HandleSubmitCryptoSystem.sign_RSA, name='sign_RSA'),
    # path('cryptosystem/rsa/verify/', HandleSubmitCryptoSystem.verify_RSA, name='verify_RSA'),
    path('cryptosystem/elgamal/create_key/', HandleSubmitCryptoSystem.gen_ElGamal_key, name='gen_ElGamal_key'),
    path('cryptosystem/elgamal/encrypt/', HandleSubmitCryptoSystem.encrypt_ElGamal, name='encrypt_ElGamal'),
    path('cryptosystem/elgamal/decrypt/', HandleSubmitCryptoSystem.decrypt_ElGamal, name='decrypt_ElGamal'),
    # path('cryptosystem/elgamal/sign/', HandleSubmitCryptoSystem.sign_ElGamal, name='sign_ElGamal'),
    # path('cryptosystem/elgamal/verify/', HandleSubmitCryptoSystem.verify_ElGamal, name='verify_ElGamal'),
    path('cryptosystem/elliptic_curve/create_key/', HandleSubmitCryptoSystem.gen_ECC_key, name='gen_ECC_key'),
    path('cryptosystem/elliptic_curve/encrypt/', HandleSubmitCryptoSystem.encrypt_Elliptic_curve, name='encrypt_Elliptic_curve'),
    path('cryptosystem/elliptic_curve/decrypt/', HandleSubmitCryptoSystem.decrypt_Elliptic_curve, name='decrypt_Elliptic_curve'),
    # path('cryptosystem/elliptic_curve/sign/', HandleSubmitCryptoSystem.sign_Elliptic_curve, name='sign_Elliptic_curve'),
    # path('cryptosystem/elliptic_curve/verify/', HandleSubmitCryptoSystem.verify_Elliptic_curve, name='verify_Elliptic_curve'),

    path('cryptosystem/shift_cipher/encrypt/', HandleSubmitCryptoSystem.encrypt_shift_cipher, name='encrypt_shift_cipher'),
    path('cryptosystem/shift_cipher/decrypt/', HandleSubmitCryptoSystem.decrypt_shift_cipher, name='decrypt_shift_cipher'),
    path('cryptosystem/affine_cipher/encrypt/', HandleSubmitCryptoSystem.encrypt_affine_cipher, name='encrypt_affine_cipher'),
    path('cryptosystem/affine_cipher/decrypt/', HandleSubmitCryptoSystem.decrypt_affine_cipher, name='decrypt_affine_cipher'),
    path('cryptosystem/vigenère_cipher/encrypt/', HandleSubmitCryptoSystem.encrypt_vigenere_cipher, name='encrypt_vigenere_cipher'),
    path('cryptosystem/vigenère_cipher/decrypt/', HandleSubmitCryptoSystem.decrypt_vigenere_cipher, name='decrypt_vigenere_cipher'),
    path('cryptosystem/hill_cipher/encrypt/', HandleSubmitCryptoSystem.encrypt_hill_cipher, name='encrypt_hill_cipher'),
    path('cryptosystem/hill_cipher/decrypt/', HandleSubmitCryptoSystem.decrypt_hill_cipher, name='decrypt_hill_cipher'),

    path('digitalsignature/digital_signature_using_rsa/create_key/', HandleSubmitCryptoSystem.gen_RSA_key, name='gen_RSA_key'),
    path('digitalsignature/digital_signature_using_rsa/sign/', HandleSubmitCryptoSystem.sign_RSA, name='sign_RSA'),
    path('digitalsignature/digital_signature_using_rsa/verify/', HandleSubmitCryptoSystem.verify_RSA, name='verify_RSA'),
]

