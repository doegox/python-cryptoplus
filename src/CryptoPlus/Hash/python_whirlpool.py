import pywhirlpool

__all__ = ['new','digest_size']

def new(data=None):
        """Create a new pure python Whirlpool hash object
        
        data =  initial input (raw string) to the hashing object
                if present, the method call update(arg) is made
        
        EXAMPLE: (http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html)
        =========
        
        >>> from CryptoPlus.Hash import python_whirlpool
        
        >>> message = "abc"
        >>> hasher = python_whirlpool.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest().upper()
        '4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5'
        
        >>> message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        >>> hasher = python_whirlpool.new()
        >>> hasher.update(message)
        >>> hasher.hexdigest().upper()
        'DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467'
        """
        return pywhirlpool.new(data)
        
digest_size = pywhirlpool.digest_size
