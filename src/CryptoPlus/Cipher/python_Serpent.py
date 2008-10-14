from blockcipher import *
from pyserpent import Serpent

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    Wrapper for pure python implementation pyserpent.py

        key = raw string containing the key
            -> when using XTS mode: the key should be a tuple containing the 2 keys needed
        mode = python_Serpent.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string, default is "all zero" IV
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import python_Serpent

    EXAMPLE:
    ---------
    NESSIE Test Vectors: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors

    >>> cipher = python_Serpent.new(('000102030405060708090A0B0C0D0E0F').decode('hex'))
    >>> (cipher.encrypt(('33B3DC87EDDD9B0F6A1F407D14919365').decode('hex'))).encode('hex').upper()
    '00112233445566778899AABBCCDDEEFF'
    >>> ( cipher.decrypt((_).decode('hex')) ).encode('hex').upper()
    '33B3DC87EDDD9B0F6A1F407D14919365'

    >>> cipher = python_Serpent.new(('FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD').decode('hex'))
    >>> (cipher.encrypt(('FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD').decode('hex'))).encode('hex').upper()
    '81F9163BDF39B5BB2932AB91DF2A5FFC'
    >>> ( cipher.decrypt((_).decode('hex')) ).encode('hex').upper()
    'FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD'

    CBC EXAMPLE:
    -------------
    >>> key = ('000102030405060708090A0B0C0D0E0F').decode('hex')
    >>> IV = ('00000000000000000000000000000000').decode('hex')
    >>> plaintext = ('33B3DC87EDDD9B0F6A1F407D14919365'*3).decode('hex')
    >>> cipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> decipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
    >>> ( decipher.decrypt(ciphertext)).encode('hex').upper()
    '33B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D14919365'
    """
    return python_Serpent(key,mode,IV,counter,segment_size)

class python_Serpent(BlockCipher):
    def __init__(self,key,mode,IV,counter,segment_size):
        if len(key) not in (16,24,32) and type(key) is not tuple:
                raise ValueError("Key should be 128, 192 or 256 bits")
        cipher_module = Serpent
        self.blocksize = 16
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
