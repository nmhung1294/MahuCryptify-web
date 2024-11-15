from django.urls import path
from MahuCrypt_app.views import HandleSubmitCryptoSystem
urlpatterns = [
    path('cryptosystem/rsa/create_key/', HandleSubmitCryptoSystem.gen_RSA_key, name='gen_RSA_key'),
    path('cryptosystem/rsa/encrypt/', HandleSubmitCryptoSystem.encrypt_RSA, name='encrypt_RSA'),
    path('cryptosystem/rsa/decrypt/', HandleSubmitCryptoSystem.decrypt_RSA, name='decrypt_RSA'),
    # path('cryptosystem/rsa/sign/', HandleSubmitCryptoSystem.sign_RSA, name='sign_RSA'),
    # path('cryptosystem/rsa/verify/', HandleSubmitCryptoSystem.verify_RSA, name='verify_RSA'),
    path('test/', HandleSubmitCryptoSystem.test, name='test'),
    path('blog/', HandleSubmitCryptoSystem.get_all_blog, name='get_all_blog'),
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
]

