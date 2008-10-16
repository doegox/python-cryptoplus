import pymd5

__all__ = ['new','digest_size']

def new(data=""):
        return pymd5.new(data)
        
digest_size = pymd5.digest_size
