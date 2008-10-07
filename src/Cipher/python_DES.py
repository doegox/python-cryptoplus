from blockcipher import *
import pyDes

def new(key,mode=MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    wrapper for pure python implementation pyDes.py

    new(key,mode=MODE_ECB,IV=None,counter=None):
        key = raw string containing the key
        mode = python_DES.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring


    EXAMPLE (test vectors from NESSIE):
    -----------------------------------
    >>> import python_DES
    >>> from binascii import hexlify, unhexlify
    >>> cipher = python_DES.new(unhexlify('7CA110454A1A6E57'))
    >>> ciphertext = cipher.encrypt(unhexlify('01A1D6D039776742'))
    >>> hexlify(ciphertext)
    '690f5b0d9a26939b'
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> hexlify(plaintext)
    '01a1d6d039776742'
    """
    return python_DES(key,mode,IV,counter)

class python_DES(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = pyDes.des(key)
        self.blocksize = self.cipher.block_size
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
