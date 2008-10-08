from blockcipher import *
import Crypto.Cipher.CAST

def new(key,mode=MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    CAST using pycrypto for algo and pycryptoplus for ciphermode

        key = raw string containing the keys
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
        IV = IV as a raw string
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode

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
    return CAST(key,mode,IV,counter)

class CAST(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = Crypto.Cipher.CAST.new(key)
        self.blocksize = Crypto.Cipher.CAST.block_size
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
