# blocksize = 128 bits
# key = up to 256 bits
#   algo supports 16, 24 and 32*8? maakt er een 32 van telkens?

import blockcipher
from pytwofish import Twofish

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    Wrapper for pure python implementation pytwofish.py

    new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
        key = raw string containing the key
        mode = python_Twofish.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring

    EXAMPLE:
    ----------
    http://www.schneier.com/code/ecb_ival.txt -> test vector I=5

    >>> import python_Twofish
    >>> from binascii import hexlify, unhexlify
    >>> cipher = python_Twofish.new(unhexlify('019F9809DE1711858FAAC3A3BA20FBC3'))
    >>> hexlify(cipher.encrypt(unhexlify('6363977DE839486297E661C6C9D668EB'))).upper()
    '816D5BD0FAE35342BF2A7412C246F752'
    >>> hexlify( cipher.decrypt(unhexlify(_)) ).upper()
    '6363977DE839486297E661C6C9D668EB'
    """
    return python_Twofish(key,mode,IV,counter)

class python_Twofish(blockcipher.BlockCipher):
    def __init__(self,key,mode,IV,counter):
        if mode == MODE_XTS:
            assert type(key) is tuple
            self.cipher = Twofish(key[1])
            self.cipher2 = Twofish(key[2])
        else:
            self.cipher = Twofish(key)
        self.blocksize = self.cipher.get_block_size()
        blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
