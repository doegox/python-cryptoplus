from blockcipher import *
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
    >>> from CryptoPlus.Cipher import DES

    EXAMPLE (test vectors from NESSIE):
    -----------------------------------

    >>> cipher = DES.new(('7CA110454A1A6E57').decode('hex'))
    >>> ciphertext = cipher.encrypt(('01A1D6D039776742').decode('hex'))
    >>> (ciphertext).encode('hex')
    '690f5b0d9a26939b'
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> (plaintext).encode('hex')
    '01a1d6d039776742'

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
