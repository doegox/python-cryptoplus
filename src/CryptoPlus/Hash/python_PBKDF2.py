import pypbkdf2
from CryptoPlus.Hash import SHA as SHA1, HMAC

__all__ = ['new']

def new(passphrase, salt, iterations=1000, digestmodule=SHA1, macmodule=HMAC):
        """PKCS#5 v2.0 Password-Based Key Derivation
        
        passphrase      = the passphrase, supplied as a raw string, to make a key from
        salt            = salt as raw string
        iterations      = amount of iterations (default = 1000)
        digestmodule    = digest function to use, supply as module
                           example: python_SHA from CryptoPlus.Hash
                           default: SHA1
        macmodule       = mac function to use, supply as module
                           example: HMAC from CryptoPlus.Hash
                           default: HMAC

                => macmodule & digestmodule construct the pseudorandom function
                        => by default: HMAC-SHA1

        Examples: (from: http://www.ietf.org/rfc/rfc3962.txt)
        ==========

        >>> from CryptoPlus.Hash import python_PBKDF2

        >>> passphrase = "password"
        >>> salt = "ATHENA.MIT.EDUraeburn"
        >>> iterations = 1
        >>> hasher = python_PBKDF2.new(passphrase,salt,iterations)
        >>> hasher.hexread(16)
        'cdedb5281bb2f801565a1122b2563515'

        >>> passphrase = "password"
        >>> salt = "ATHENA.MIT.EDUraeburn"
        >>> iterations = 1200
        >>> hasher = python_PBKDF2.new(passphrase,salt,iterations)
        >>> hasher.hexread(32)
        '5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13'

        >>> passphrase = "X"*64
        >>> salt = "pass phrase equals block size"
        >>> iterations = 1200
        >>> hasher = python_PBKDF2.new(passphrase,salt,iterations)
        >>> hasher.hexread(32)
        '139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1'

        >>> passphrase = "X"*65
        >>> salt = "pass phrase exceeds block size"
        >>> iterations = 1200
        >>> hasher = python_PBKDF2.new(passphrase,salt,iterations)
        >>> hasher.hexread(32)
        '9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a'
        """
        return pypbkdf2.PBKDF2(passphrase, salt, iterations, digestmodule, macmodule)
