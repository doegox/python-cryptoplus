from blockcipher import *
try:
    import Crypto.Cipher.RC5
except ImportError:
    print "Crypto.Cipher.RC5 isn't available. You're probably using the Debian pycrypto version. Install the original pycrypto for RC5."
    raise

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None,rounds=12,word_size=32):
    """Create a new cipher object

    RC5 using pycrypto for algo and pycryptoplus for ciphermode

        key = raw string containing the keys
              multiple of 8 bits between 0 <-> 2040 bits
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
        IV = IV as a raw string, default is "all zero" IV
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode
        rounds = amount of rounds, default = 12
                 minimum 12 and multiple of 2
        word_size = RC5 word size (bits), supported = 16 and 32, default = 32
                    RC5 encrypts blocks of size 2*word_size

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import RC5

    https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    -----------------------------------------
    >>> key = "00000000000000000000000000000000".decode('hex')
    >>> plaintext = "0000000000000000".decode('hex')
    >>> rounds = 12
    >>> cipher = RC5.new(key,RC5.MODE_ECB,rounds=rounds)
    >>> cipher.encrypt(plaintext).encode('hex')
    '21a5dbee154b8f6d'
    """
    return RC5(key,mode,IV,counter,rounds,word_size,segment_size)

class RC5(BlockCipher):
    def __init__(self,key,mode,IV,counter,rounds,word_size,segment_size):
        cipher_module = Crypto.Cipher.RC5.new
        args = {'rounds':rounds,'word_size':word_size}
        self.blocksize = (2*word_size)/8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
