from Crypto.Hash import RIPEMD

def new(data=None):
        """Create a new RIPEMD-160 hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: 
        =========
        
        >>> from CryptoPlus.Hash import RIPEMD
        
        >>> message = "abc"
        >>> hasher = RIPEMD.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
        
        >>> message = "message digest"
        >>> hasher = RIPEMD.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest()
        '5d0689ef49d2fae572b881b123a85ffa21595f36'
        """
        return RIPEMD.new(data)
