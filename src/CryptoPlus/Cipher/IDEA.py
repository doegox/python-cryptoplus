from blockcipher import *
try:
    import Crypto.Cipher.IDEA
except ImportError:
    print "Crypto.Cipher.IDEA isn't available. You're probably using the Debian pycrypto version. Install the original pycrypto for IDEA."
    raise

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    IDEA using pycrypto for algo and pycryptoplus for ciphermode

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
    >>> from CryptoPlus.Cipher import IDEA

    https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    -----------------------------------------
    >>> from CryptoPlus.Cipher import IDEA
    >>> key = "2BD6459F82C5B300952C49104881FF48".decode('hex')
    >>> plaintext = "F129A6601EF62A47".decode('hex')
    >>> cipher = IDEA.new(key,IDEA.MODE_ECB,)
    >>> cipher.encrypt(plaintext).encode('hex').upper()
    'EA024714AD5C4D84'
    """
    return IDEA(key,mode,IV,counter,segment_size)

class IDEA(BlockCipher):
    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = Crypto.Cipher.IDEA.new
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
