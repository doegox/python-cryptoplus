from pysha512 import sha512

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python SHA-512 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: FIPS 180-2
        =========
        
        >>> from CryptoPlus.Hash import python_SHA512
        
        >>> message = "abc"
        >>> hasher = python_SHA512.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
        
        >>> message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        >>> hasher = python_SHA512.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'
        """
        return sha512(data)
        
digest_size = sha512.digest_size
