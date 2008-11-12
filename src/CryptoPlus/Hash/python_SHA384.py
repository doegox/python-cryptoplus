from pysha384 import sha384

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python SHA-384 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: FIPS 180-2
        =========
        
        >>> from CryptoPlus.Hash import python_SHA384
        
        >>> message = "abc"
        >>> hasher = python_SHA384.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'

        >>> message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        >>> hasher = python_SHA384.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039'
        """
        return sha384(data)
        
digest_size = sha384.digest_size
