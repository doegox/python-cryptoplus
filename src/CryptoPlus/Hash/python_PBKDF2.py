import pypbkdf2
from CryptoPlus.Hash import SHA1, HMAC

__all__ = ['new']

def new(passphrase, salt, iterations=1000, digestmodule=SHA1, macmodule=HMAC):
        return pypbkdf2.PBKDF2(passphrase, salt, iterations, digestmodule, macmodule)
