from pysha224 import sha224

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python SHA-224 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: FIPS 180-2
        =========
        
        >>> from CryptoPlus.Hash import python_SHA224
        
        >>> message = "abc"
        >>> hasher = python_SHA224.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'
        
        >>> message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        >>> hasher = python_SHA224.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'
        """
        return sha224(data)
        
digest_size = sha224.digest_size
