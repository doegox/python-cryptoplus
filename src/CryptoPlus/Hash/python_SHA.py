import pysha

__all__ = ['new','digest_size']

def new(data=""):
        return pysha.new(data)
        
digest_size = pysha.digest_size
