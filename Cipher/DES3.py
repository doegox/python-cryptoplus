import blockcipher
import Crypto.Cipher.DES3

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6

def new(key,mode=blockcipher.MODE_ECB,IV=None):
	return DES3(key,mode,IV)

class DES3(blockcipher.BlockCipher):
	#need test vectors
	"""DES using pycrypto for algo en pycryptoplus for ciphermode
	
	EXAMPLE:
	>>> import DES3	
	>>> from binascii import hexlify, unhexlify
	>>> cipher = DES3.new(unhexlify(''))
	>>> ciphertext = cipher.encrypt(unhexlify(''))
	>>> hexlify(ciphertext)
	''
	>>> plaintext = cipher.decrypt(ciphertext)
	>>> hexlify(plaintext)
	''
	"""
	def __init__(self,key,mode,IV):
		self.cipher = Crypto.Cipher.DES3.new(key)
		self.blocksize = Crypto.Cipher.DES3.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
