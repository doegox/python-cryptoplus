# key size = 0 - 2040 bits
# blocksize = 32, 64 or 128 bits
import blockcipher
try:
	import Crypto.Cipher.RC5
except ImportError:
	print "Crypto.Cipher.RC5 isn't available. You're probably using the Debian pycrypto version. Install the original pycrypto for RC5."
	raise

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	"""Create a new cipher object

	RC5 using pycrypto for algo en pycryptoplus for ciphermode

	new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
		key = raw string containing the keys
		mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/CMAC
		IV = IV as a raw string
			-> only needed for CBC mode
		counter = counter object (Cipher/util.py:Counter)
			-> only needed for CTR mode

	https://www.cosic.esat.kuleuven.be/nessie/testvectors/
	-----------------------------------------
	>>> from CryptoPlus.Cipher import RC5
	>>> key = "000102030405060708090A0B0C0D0E0F".decode('hex')
	>>> plaintext = "96950DDA654A3D62".decode('hex')
	>>> cipher = RC5.new(key,RC5.MODE_ECB)
	>>> cipher.encrypt(plaintext).encode('hex').upper()
	'0011223344556677'
	"""
	return RC5(key,mode,IV,counter)

class RC5(blockcipher.BlockCipher):
	def __init__(self,key,mode,IV,counter):
		if mode == MODE_XTS:
			#XTS implementation only works with blocksizes of 16 bytes
			assert blocksize == 16
			assert type(key) is tuple
			self.cipher = Crypto.Cipher.RC5.new(key[0])
			self.cipher2 = Crypto.Cipher.RC5.new(key[1])
		elif mode == MODE_CMAC:
			#CMAC implementation only supports blocksizes of 8 and 16 bytes
			assert blocksize in (8,16)
			self.cipher = Crypto.Cipher.RC5.new(key)
		else:
			self.cipher = Crypto.Cipher.RC5.new(key)
		self.blocksize = Crypto.Cipher.RC5.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
