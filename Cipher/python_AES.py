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

def new(key,mode=blockcipher.MODE_ECB,IV=None):
	return python_AES(key,mode,IV)

class python_AES(blockcipher.BlockCipher):
	"""Wrapper for pure python implementation rijndael.py

	EXAMPLE:
	----------
	>>> import python_AES
	>>> cipher = python_AES.new('0123456789012345')
	>>> cipher.encrypt('0123456789012345')
	'_}\\xf0\\xbf\\x10:\\x8cJ\\xe6\\xfa\\xad\\x99\\x06\\xac;*'
	>>> cipher.decrypt(_)
	'0123456789012345'

	CBC EXAMPLE (plaintext = 3 blocksizes):
	-----------------------------------------
	>>> from binascii import hexlify,unhexlify
	>>> import python_AES
	>>> key = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
	>>> IV = unhexlify('000102030405060708090a0b0c0d0e0f')
	>>> plaintext1 = unhexlify('6bc1bee22e409f96e93d7e117393172a')
	>>> plaintext2 = unhexlify('ae2d8a571e03ac9c9eb76fac45af8e51')
	>>> plaintext3 = unhexlify('30c81c46a35ce411e5fbc1191a0a52ef')
	>>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
	>>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
	>>> hexlify(ciphertext)
	'7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
	>>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
	>>> plaintext = decipher.decrypt(ciphertext)
	>>> hexlify(plaintext)
	'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

	OR: supply plaintext as seperate pieces:
	------------------------------------------
	>>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
	>>> hexlify( cipher.encrypt(plaintext1 + plaintext2[:-2]) )
	'7649abac8119b246cee98e9b12e9197d'
	>>> hexlify( cipher.encrypt(plaintext2[-2:] + plaintext3) )
	'5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
	>>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
	>>> hexlify(decipher.decrypt(ciphertext[:22]))
	'6bc1bee22e409f96e93d7e117393172a'
	>>> hexlify(decipher.decrypt(ciphertext[22:]))
	'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'
	"""
	def __init__(self,key,mode,IV):
		self.cipher = rijndael(key, 16)
		self.blocksize = 16
		blockcipher.BlockCipher.__init__(self,key,mode,IV)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
