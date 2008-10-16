import pywhirlpool

__all__ = ['new','digest_size']

def new(data=""):
        return pywhirlpool.new(data)
        
digest_size = pywhirlpool.digest_size
