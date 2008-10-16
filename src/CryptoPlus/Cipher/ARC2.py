from blockcipher import *
import Crypto.Cipher.ARC2
import Crypto
from pkg_resources import parse_version

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None,effective_keylen=None):
    """Create a new cipher object

    ARC2 using pycrypto for algo and pycryptoplus for ciphermode

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
        effective_keylen = how much bits to effectively use from the supplied key
            -> will only be used when the pycrypto version on your system is >2.0.1

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import ARC2

    http://www.ietf.org/rfc/rfc2268.txt
    Doctest will fail when using pycrypto 2.0.1 and older
    ------------------------------------
    >>> key = "0000000000000000".decode('hex')
    >>> plaintext = "0000000000000000".decode('hex')
    >>> ek = 63
    >>> cipher = ARC2.new(key,ARC2.MODE_ECB,effective_keylen=ek)
    >>> cipher.encrypt(plaintext).encode('hex')
    'ebb773f993278eff'
    """
    return ARC2(key,mode,IV,counter,effective_keylen,segment_size)

class ARC2(BlockCipher):
    def __init__(self,key,mode,IV,counter,effective_keylen,segment_size):
        # pycrypto versions newer than 2.0.1 will have support for "effective_keylen"
        if parse_version(Crypto.__version__) <= parse_version("2.0.1"):
            cipher_module = Crypto.Cipher.ARC2.new
            args = {}
        else:
            cipher_module = Crypto.Cipher.ARC2.new
            args = {'effective_keylen':effective_keylen}
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
