from blockcipher import *
from pypresent import Present

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None,rounds=32):
    """Create a new cipher object

    Wrapper for pure python implementation rijndael.py

        key = raw string containing the key, AES-128..256 will be selected according to the key length
        mode = python_PRESENT.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string, default is "all zero" IV
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
                rounds = amount of rounds
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode
        rounds = amount of rounds, default = 32

    Notes:
        - Always construct a seperate cipher object for encryption and decryption. Once a cipher object has been used for encryption,
          it can't be used for decryption because it keeps a state (if necessary) for the IV.

        EXAMPLES:
        **********
        IMPORTING:
        -----------
        >>> from CryptoPlus.Cipher import python_PRESENT

        ECB Test Vectors:
        ------------------
        >>> key = "00000000000000000000".decode('hex')
        >>> plain = "0000000000000000".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
        >>> cipher.encrypt(plain).encode('hex')
        '5579c1387b228445'
        
        >>> key = "00000000000000000000000000000000".decode('hex')
        >>> plain = "0000000000000000".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB,rounds=64)
        >>> cipher.encrypt(plain).encode('hex')
        '59a27d01607ebf05'
        
        >>> key = "00000000000000000000".decode('hex')
        >>> plain = "0000000000000000".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB,rounds=64)
        >>> cipher.encrypt(plain).encode('hex')
        '13991dd588bc1288'
        
        Test Vectors for maximum rounds supported by PRESENT reference C code:
        -----------------------------------------------------------------------
        >>> key = "0123456789abcdef0123".decode('hex')
        >>> plain = "0123456789abcdef".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB,rounds=65534)
        >>> ciphertext = cipher.encrypt(plain)
        >>> ciphertext.encode('hex')
        'a140dc5d7175ca20'
        >>> cipher.decrypt(ciphertext).encode('hex')
        '0123456789abcdef'
        
        >>> key = "0123456789abcdef0123456789abcdef".decode('hex')
        >>> plain = "0123456789abcdef".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB,rounds=65534)
        >>> ciphertext = cipher.encrypt(plain)
        >>> ciphertext.encode('hex')
        '21007772e5d4ef14'
        >>> cipher.decrypt(ciphertext).encode('hex')
        '0123456789abcdef'
        """
    return python_PRESENT(key,mode,IV,counter,rounds,segment_size)

class python_PRESENT(BlockCipher):
    key_error_message = "Key should be 80 or 128 bits"

    def __init__(self,key,mode,IV,counter,rounds,segment_size):
        cipher_module = Present
        args = {'rounds':rounds}
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

    def keylen_valid(self,key):
        return len(key) in (10,16)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
