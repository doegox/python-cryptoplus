from blockcipher import *
from pypresent import Present

def new(key,mode=MODE_ECB,IV=None,counter=None,rounds=32):
    """Create a new cipher object

    Wrapper for pure python implementation rijndael.py

        key = raw string containing the key, AES-128..256 will be selected according to the key length
            -> when using XTS mode: the key should be a tuple containing the 2 keys needed
        mode = python_PRESENT.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
                rounds = amount of rounds
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
        '67d38fb0f5a371fd'
        
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
        'c913bc146bc89c4e'
        >>> cipher.decrypt(ciphertext).encode('hex')
        '0123456789abcdef'
        """
    return python_PRESENT(key,mode,IV,counter,rounds)

class python_PRESENT(BlockCipher):
    def __init__(self,key,mode,IV,counter,rounds):
        self.cipher = Present(key,rounds)
        self.blocksize = 8
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
