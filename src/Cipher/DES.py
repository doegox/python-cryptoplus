from blockcipher import *
import Crypto.Cipher.DES

def new(key,mode=MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    DES using pycrypto for algo and pycryptoplus for ciphermode

    new(key,mode=MODE_ECB,IV=None,counter=None):
        key = raw string containing the keys
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
        IV = IV as a raw string
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode

    EXAMPLE (test vectors from NESSIE):
    -----------------------------------
    >>> import DES
    >>> from binascii import hexlify, unhexlify
    >>> cipher = DES.new(unhexlify('7CA110454A1A6E57'))
    >>> ciphertext = cipher.encrypt(unhexlify('01A1D6D039776742'))
    >>> hexlify(ciphertext)
    '690f5b0d9a26939b'
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> hexlify(plaintext)
    '01a1d6d039776742'

    """
    return DES(key,mode,IV,counter)

class DES(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = Crypto.Cipher.DES.new(key)
        self.blocksize = Crypto.Cipher.DES.block_size
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
