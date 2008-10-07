from blockcipher import *
import Crypto.Cipher.DES3

def new(key,mode=MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    DES using pycrypto for algo and pycryptoplus for ciphermode

    new(key,mode=MODE_ECB,IV=None,counter=None):
        key = raw string containing the 2/3 keys
            - DES-EDE2: supply 2 keys as 1 single concatenated 16byte key= key1|key2
            - DES-EDE3: supply 3 keys as 1 single concatenated 24byte key= key1|key2|key3
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC, default is ECB
        IV = IV as a raw string
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode


    CBC TDES-EDE3 EXAMPLE: (using test vectors from http://csrc.nist.gov/groups/STM/cavp/documents/des/DESMMT.pdf)
    ------------
    >>> import DES3
    >>> from binascii import hexlify, unhexlify
    >>> key = unhexlify('37ae5ebf46dff2dc0754b94f31cbb3855e7fd36dc870bfae')
    >>> IV = unhexlify('3d1de3cc132e3b65')
    >>> cipher = DES3.new(key, DES3.MODE_CBC, IV)
    >>> ciphertext = cipher.encrypt(unhexlify('84401f78fe6c10876d8ea23094ea5309'))
    >>> hexlify(ciphertext)
    '7b1f7c7e3b1c948ebd04a75ffba7d2f5'
    >>> decipher = DES3.new(key, DES3.MODE_CBC, IV)
    >>> plaintext = decipher.decrypt(ciphertext)
    >>> hexlify(plaintext)
    '84401f78fe6c10876d8ea23094ea5309'

    CMAC TDES-EDE3 EXAMPLE: (http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf)
    -------------
    >>> key = '8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5'.decode('hex')
    >>> plaintext = '6bc1bee22e409f96e93d7e117393172aae2d8a57'.decode('hex')
    >>> cipher = DES3.new(key, DES3.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')
    '743ddbe0ce2dc2ed'

    CMAC TDES-EDE2 EXAMPLE:
    -----------------------
    testvector: http://csrc.nist.gov/groups/STM/cavp/documents/mac/cmactestvectors.zip

    >>> key1 = "5104f2c76180c1d3".decode('hex')
    >>> key2 = "b9df763e31ada716".decode('hex')
    >>> key = key1 + key2
    >>> plaintext = 'a6866be2fa6678f264a19c4474968e3f4eec24f5086d'.decode('hex')
    >>> cipher = DES3.new(key, DES3.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')
    '32e7758f3f614dbf'
    """
    return DES3(key,mode,IV,counter)

class DES3(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = Crypto.Cipher.DES3.new(key)
        self.blocksize = Crypto.Cipher.DES3.block_size
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
