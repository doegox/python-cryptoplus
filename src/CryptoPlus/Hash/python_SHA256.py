from pysha256 import sha256

__all__ = ['new','digest_size']

def new(data=""):
        return sha256(data)
        
digest_size = sha256.digest_size
