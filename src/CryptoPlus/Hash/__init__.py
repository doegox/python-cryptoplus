# hash functions of pycrypto can be just imported
# wrapping might be a better idea if docstrings need to be expanded
# wrapping in Cipher was needed to make the new chaining modes available
from Crypto.Hash import SHA, SHA256, MD5, MD2, MD4, HMAC

__all__ = ["SHA","SHA256","MD5","MD2","MD4","HMAC","RIPEMD"]

