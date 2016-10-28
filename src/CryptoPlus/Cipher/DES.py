from __future__ import absolute_import
from .blockcipher import *
import Crypto.Cipher.DES

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    DES using pycrypto for algo and pycryptoplus for ciphermode

        key = raw string containing the keys
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
        IV = IV as a raw string, default is "all zero" IV
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> import codecs
    >>> from CryptoPlus.Cipher import DES

    EXAMPLE (test vectors from NESSIE):
    -----------------------------------

    >>> cipher = DES.new(codecs.decode('7CA110454A1A6E57', 'hex'))
    >>> ciphertext = cipher.encrypt(codecs.decode('01A1D6D039776742', 'hex'))
    >>> codecs.encode(ciphertext, 'hex')
    b'690f5b0d9a26939b'
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> codecs.encode(plaintext, 'hex')
    b'01a1d6d039776742'

    """
    return DES(key,mode,IV,counter,segment_size)

class DES(BlockCipher):
    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = Crypto.Cipher.DES.new
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
