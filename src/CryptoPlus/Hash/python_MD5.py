import pymd5

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python MD5 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: (http://www.rfc-editor.org/rfc/rfc1321.txt)
        =========
        
        >>> from CryptoPlus.Hash import MD5
        
        >>> message = "abc"
        >>> hasher = MD5.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '900150983cd24fb0d6963f7d28e17f72'
        
        >>> message = "message digest"
        >>> hasher = MD5.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        'f96b697d7cb7938d525a2f31aaf161d0'
        """
        return pymd5.new(data)
        
digest_size = pymd5.digest_size
