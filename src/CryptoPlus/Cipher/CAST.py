from blockcipher import *
import Crypto.Cipher.CAST

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    CAST using pycrypto for algo and pycryptoplus for ciphermode

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
    >>> from CryptoPlus.Cipher import CAST

    ECB example: http://www.rfc-editor.org/rfc/rfc2144.txt
    -------------
    128 bit key

    >>> key = "0123456712345678234567893456789A".decode('hex')
    >>> plaintext = "0123456789ABCDEF".decode('hex')
    >>> cipher = CAST.new(key,CAST.MODE_ECB,)
    >>> cipher.encrypt(plaintext).encode('hex')
    '238b4fe5847e44b2'

    40 bit key
    >>> from CryptoPlus.Cipher import CAST
    >>> key = "0123456712".decode('hex')
    >>> plaintext = "0123456789ABCDEF".decode('hex')
    >>> cipher = CAST.new(key,CAST.MODE_ECB,)
    >>> cipher.encrypt(plaintext).encode('hex').upper()
    '7AC816D16E9B302E'
    """
    return CAST(key,mode,IV,counter,segment_size)

class CAST(BlockCipher):
    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = Crypto.Cipher.CAST.new
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
