from pysha224 import sha224

__all__ = ['new','digest_size']

def new(data=""):
        return sha224(data)
        
digest_size = sha224.digest_size
