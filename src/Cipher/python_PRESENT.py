import blockcipher
from pypresent import Present

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None,rounds=32):
    """Create a new cipher object

    Wrapper for pure python implementation rijndael.py

    new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None,rounds=32):
        key = raw string containing the key, AES-128..256 will be selected according to the key length
            -> when using XTS mode: the key should be a tuple containing the 2 keys needed
        mode = python_PRESENT.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string
            -> needed for CBC, CFB and OFB mode
        counter = counter object (Cipher/util.py:Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
                rounds = amount of rounds

    Notes:
        - Always construct a seperate cipher object for encryption and decryption. Once a cipher object has been used for encryption,
          it can't be used for decryption because it keeps a state (if necessary) for the IV.


        ECB Test Vectors:
        ------------------
        >>> from CryptoPlus.Cipher import python_PRESENT

        >>> key = "00000000000000000000".decode('hex')
        >>> plain = "0000000000000000".decode('hex')
        >>> cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
        >>> cipher.encrypt(plain).encode('hex')
        '5579c1387b228445'
        """
    return python_PRESENT(key,mode,IV,counter,rounds)

class python_PRESENT(blockcipher.BlockCipher):
    def __init__(self,key,mode,IV,counter,rounds):
        if mode == MODE_XTS:
            assert type(key) is tuple
            self.cipher = Present(key[0],rounds)
            self.cipher2 = Present(key[1],rounds)
        else:
            self.cipher = Present(key,rounds)
        self.blocksize = 8
        blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
