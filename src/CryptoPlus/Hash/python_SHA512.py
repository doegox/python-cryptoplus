from pysha512 import sha512

__all__ = ['new','digest_size']

def new(data=""):
        return sha512(data)
        
digest_size = sha512.digest_size
