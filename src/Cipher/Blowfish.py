from blockcipher import *
import Crypto.Cipher.Blowfish

def new(key,mode=MODE_ECB,IV=None,counter=None):
    """Create a new cipher object

    Blowfish using pycrypto for algo and pycryptoplus for ciphermode

        key = raw string containing the key
        mode = Blowfish.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
        IV = IV as a raw string
            -> only needed for CBC mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode

    ECB EXAMPLE: http://www.schneier.com/code/vectors.txt
    -------------
    >>> import Blowfish
    >>> from binascii import hexlify, unhexlify
    >>> cipher = Blowfish.new(unhexlify('0131D9619DC1376E'))
    >>> hexlify( cipher.encrypt(unhexlify('5CD54CA83DEF57DA')) )
    'b1b8cc0b250f09a0'
    >>> hexlify( cipher.decrypt(unhexlify(_)) )
    '5cd54ca83def57da'

    CBC, CFB, OFB EXAMPLE: http://www.schneier.com/code/vectors.txt
    ----------------------
    >>> from binascii import hexlify,unhexlify
    >>> key = unhexlify('0123456789ABCDEFF0E1D2C3B4A59687')
    >>> IV = unhexlify('FEDCBA9876543210')
    >>> plaintext = unhexlify('37363534333231204E6F77206973207468652074696D6520')
    >>> cipher = Blowfish.new(key,Blowfish.MODE_CBC,IV)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> hexlify(ciphertext).upper()
    '6B77B4D63006DEE605B156E27403979358DEB9E7154616D9'


    >>> key = '0123456789ABCDEFF0E1D2C3B4A59687'.decode('hex')
    >>> iv = 'FEDCBA9876543210'.decode('hex')
    >>> plaintext = '37363534333231204E6F77206973207468652074696D6520666F722000'.decode('hex')

    >>> cipher = Blowfish.new(key,Blowfish.MODE_CBC,iv)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> hexlify(ciphertext).upper()
    '6B77B4D63006DEE605B156E27403979358DEB9E7154616D9'

    >>> cipher = Blowfish.new(key,Blowfish.MODE_CFB,iv)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> hexlify(ciphertext).upper()
    'E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3'

    >>> cipher = Blowfish.new(key,Blowfish.MODE_OFB,iv)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> hexlify(ciphertext).upper()
    'E73214A2822139CA62B343CC5B65587310DD908D0C241B2263C2CF80DA'
    """
    return Blowfish(key,mode,IV,counter)

class Blowfish(BlockCipher):
    def __init__(self,key,mode,IV,counter):
        self.cipher = Crypto.Cipher.Blowfish.new(key)
        self.blocksize = Crypto.Cipher.Blowfish.block_size
        BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
