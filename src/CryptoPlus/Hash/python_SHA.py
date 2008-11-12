import pysha

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python SHA hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: FIPS 180-2
        =========
        
        >>> from CryptoPlus.Hash import python_SHA
        
        >>> message = "abc"
        >>> hasher = python_SHA.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        'a9993e364706816aba3e25717850c26c9cd0d89d'
        
        >>> message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        >>> hasher = python_SHA.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
        """
        return pysha.new(data)
        
digest_size = pysha.digest_size
