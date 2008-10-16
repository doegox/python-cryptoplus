import pysha256

__all__ = ['new','digest_size']

def new(data=""):
        return pysha256.new(data)
        
digest_size = pysha256.digest_size
