# key size = 16bytes
# blocksize = 8bytes
import blockcipher
try:
    import Crypto.Cipher.IDEA
except ImportError:
    print "Crypto.Cipher.IDEA isn't available. You're probably using the Debian pycrypto version. Install the original pycrypto for IDEA."
    raise

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
#IDEA blocksize is 8bytes, XTS requires 16bytes
#MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    IDEA using pycrypto for algo en pycryptoplus for ciphermode

    new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
        key = raw string containing the keys
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC
        IV = IV as a raw string
            -> only needed for CBC mode
        counter = counter object (Cipher/util.py:Counter)
            -> only needed for CTR mode

    https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    -----------------------------------------
    >>> from CryptoPlus.Cipher import IDEA
    >>> key = "2BD6459F82C5B300952C49104881FF48".decode('hex')
    >>> plaintext = "F129A6601EF62A47".decode('hex')
    >>> cipher = IDEA.new(key,IDEA.MODE_ECB,)
    >>> cipher.encrypt(plaintext).encode('hex').upper()
    'EA024714AD5C4D84'
    """
    return IDEA(key,mode,IV,counter)

class IDEA(blockcipher.BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = Crypto.Cipher.IDEA.new(key)
        self.blocksize = Crypto.Cipher.IDEA.block_size
        blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
