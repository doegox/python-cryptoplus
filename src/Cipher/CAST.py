# variable key size
# blocksize = 8bytes
import blockcipher
import Crypto.Cipher.CAST

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
#CAST blocksize is 8bytes, XTS requires 16bytes
#MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	"""Create a new cipher object

	CAST using pycrypto for algo en pycryptoplus for ciphermode

	new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
		key = raw string containing the keys
		mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC
		IV = IV as a raw string
			-> only needed for CBC mode
		counter = counter object (Cipher/util.py:Counter)
			-> only needed for CTR mode

	http://www.rfc-editor.org/rfc/rfc2144.txt
	-----------------------------------------
	>>> from CryptoPlus.Cipher import CAST
	>>> key = "0123456712345678234567893456789A".decode('hex')
	>>> plaintext = "0123456789ABCDEF".decode('hex')
	>>> cipher = CAST.new(key,CAST.MODE_ECB,)
	>>> cipher.encrypt(plaintext).encode('hex')
	'238b4fe5847e44b2'
	"""
	return CAST(key,mode,IV,counter)

class CAST(blockcipher.BlockCipher):
	def __init__(self,key,mode,IV,counter):
		self.cipher = Crypto.Cipher.CAST.new(key)
		self.blocksize = Crypto.Cipher.CAST.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
