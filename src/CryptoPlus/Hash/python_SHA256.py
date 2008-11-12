from pysha256 import sha256

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python SHA-256 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: FIPS 180-2
        =========
        
        >>> from CryptoPlus.Hash import python_SHA256
        
        >>> message = "abc"
        >>> hasher = python_SHA256.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
        
        >>> message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        >>> hasher = python_SHA256.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
        """
        return sha256(data)
        
digest_size = sha256.digest_size
