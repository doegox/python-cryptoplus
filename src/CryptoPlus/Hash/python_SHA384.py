from pysha384 import sha384

__all__ = ['new','digest_size']

def new(data=""):
        return sha384(data)
        
digest_size = sha384.digest_size
