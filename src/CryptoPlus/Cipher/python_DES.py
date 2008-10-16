from blockcipher import *
import pyDes

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    wrapper for pure python implementation pyDes.py

        key = raw string containing the key
        mode = python_DES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string, default is "all zero" IV
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import python_DES

    EXAMPLE (test vectors from NESSIE):
    -----------------------------------
    >>> cipher = python_DES.new(('7CA110454A1A6E57').decode('hex'))
    >>> ciphertext = cipher.encrypt(('01A1D6D039776742').decode('hex'))
    >>> (ciphertext).encode('hex')
    '690f5b0d9a26939b'
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> (plaintext).encode('hex')
    '01a1d6d039776742'
    """
    return python_DES(key,mode,IV,counter,segment_size)

class python_DES(BlockCipher):
    key_error_message = ("Key should be 64 bits")

    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = pyDes.des
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size)

    def keylen_valid(self,key):
        return len(key) == 8

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
