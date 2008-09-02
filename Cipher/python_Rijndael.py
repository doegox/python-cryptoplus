# wrapper for rijndael.py. rijndael.py can be found here:
#	http://bitconjurer.org/rijndael.py
# other possible python AES implementations:
#	http://psionicist.online.fr/code/rijndael.py.txt
#	http://jclement.ca/software/pyrijndael/

import blockcipher
from rijndael import rijndael

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None,blocksize=None):
	return python_Rijndael(key,mode,IV,counter,blocksize)

class python_Rijndael(blockcipher.BlockCipher):
	"""Wrapper for pure python implementation rijndael.py

	EXAMPLE:
	--------
	24 byte block, 32 byte key (http://fp.gladman.plus.com/cryptography_technology/rijndael/)
	>>> import python_Rijndael
	>>> key = '2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe'.decode('hex')
	>>> plaintext ='3243f6a8885a308d313198a2e03707344a4093822299f31d'.decode('hex')
	>>> cipher = python_Rijndael.new(key,python_Rijndael.MODE_ECB,blocksize=24)
	>>> cipher.encrypt(plaintext).encode('hex')
	'0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c'

	CBC EXAMPLE (plaintext = 3 blocksizes) (AES):
	-----------------------------------------
	>>> import python_Rijndael
	>>> from binascii import hexlify,unhexlify
	>>> key = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
	>>> IV = unhexlify('000102030405060708090a0b0c0d0e0f')
	>>> plaintext1 = unhexlify('6bc1bee22e409f96e93d7e117393172a')
	>>> plaintext2 = unhexlify('ae2d8a571e03ac9c9eb76fac45af8e51')
	>>> plaintext3 = unhexlify('30c81c46a35ce411e5fbc1191a0a52ef')
	>>> cipher = python_Rijndael.new(key,python_Rijndael.MODE_CBC,IV,blocksize=16)
	>>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
	>>> hexlify(ciphertext)
	'7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
	>>> decipher = python_Rijndael.new(key,python_Rijndael.MODE_CBC,IV,blocksize=16)
	>>> plaintext = decipher.decrypt(ciphertext)
	>>> hexlify(plaintext)
	'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'
	"""
	def __init__(self,key,mode,IV,counter,blocksize):
		assert len(key) in (16, 24, 32)
		assert blocksize in (16, 24, 32)
		if mode == MODE_XTS:
			assert len(key) == 32
			self.cipher = rijndael(key[:16], blocksize)
			self.cipher2 = rijndael(key[16:], blocksize)
		else:
			self.cipher = rijndael(key, blocksize)
		self.blocksize = blocksize
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
