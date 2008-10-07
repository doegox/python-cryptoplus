from blockcipher import *
from pyserpent import Serpent

def new(key,mode=MODE_ECB,IV=None,counter=None):
    #key length can be any multiple of 4 bytes between 0 and 32 bytes (=256bits)
    """Create a new cipher object

    Wrapper for pure python implementation pyserpent.py

    new(key,mode=MODE_ECB,IV=None,counter=None):
        key = raw string containing the key
        mode = python_Serpent.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring

    EXAMPLE:
    ---------
    NESSIE Test Vectors: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors

    >>> import python_Serpent
    >>> from binascii import hexlify, unhexlify
    >>> cipher = python_Serpent.new(unhexlify('000102030405060708090A0B0C0D0E0F'))
    >>> hexlify(cipher.encrypt(unhexlify('33B3DC87EDDD9B0F6A1F407D14919365'))).upper()
    '00112233445566778899AABBCCDDEEFF'
    >>> hexlify( cipher.decrypt(unhexlify(_)) ).upper()
    '33B3DC87EDDD9B0F6A1F407D14919365'

    >>> import python_Serpent
    >>> from binascii import hexlify, unhexlify
    >>> cipher = python_Serpent.new(unhexlify('FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD'))
    >>> hexlify(cipher.encrypt(unhexlify('FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD'))).upper()
    '81F9163BDF39B5BB2932AB91DF2A5FFC'
    >>> hexlify( cipher.decrypt(unhexlify(_)) ).upper()
    'FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD'

    CBC EXAMPLE:
    -------------
    >>> from binascii import hexlify,unhexlify
    >>> import python_Serpent
    >>> key = unhexlify('000102030405060708090A0B0C0D0E0F')
    >>> IV = unhexlify('00000000000000000000000000000000')
    >>> plaintext = unhexlify('33B3DC87EDDD9B0F6A1F407D14919365'*3)
    >>> cipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> decipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
    >>> hexlify( decipher.decrypt(ciphertext)).upper()
    '33B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D14919365'
    """
    return python_Serpent(key,mode,IV,counter)

class python_Serpent(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        if mode == MODE_XTS:
            assert type(key) is tuple
            self.cipher = Serpent(key[0])
            self.cipher2 = Serpent(key[1])
        else:
            self.cipher = Serpent(key)
        self.blocksize = self.cipher.get_block_size()
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
