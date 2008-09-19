# source of the used python implementation of blowfish
#	http://www.michaelgilfix.com/files/blowfish.py
# other possibility:
#	http://www.4dsolutions.net/cgi-bin/py2html.cgi?script=/ocn/python/blowfish.py
#		=> difficulties: doesn't define a class, only functions
#				 

import blockcipher
from pyserpent import Serpent

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	#key length can be any multiple of 4 bytes between 0 and 32 bytes (=256bits)
	"""Create a new cipher object

	Wrapper for pure python implementation pyserpent.py

	new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
		key = raw string containing the key
		mode = python_Serpent.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC
			-> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
		IV = IV as a raw string
			-> needed for CBC, CFB and OFB mode
		counter = counter object (Cipher/util.py:Counter)
			-> only needed for CTR mode
			-> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
				see CTR example further on in the docstring

	EXAMPLE:
	----------
	>>> import python_Serpent
	>>> from binascii import hexlify, unhexlify
	>>> cipher = python_Serpent.new(unhexlify('000102030405060708090A0B0C0D0E0F'))
	>>> hexlify(cipher.encrypt(unhexlify('33B3DC87EDDD9B0F6A1F407D14919365'))).upper()
	'00112233445566778899AABBCCDDEEFF'
	>>> hexlify( cipher.decrypt(unhexlify(_)) ).upper()
	'33B3DC87EDDD9B0F6A1F407D14919365'

	CBC EXAMPLE:
	-----------------------------------------
	>>> from binascii import hexlify,unhexlify
	>>> import python_Serpent
	>>> key = unhexlify('000102030405060708090A0B0C0D0E0F')
	>>> IV = unhexlify('00000000000000000000000000000000')
	>>> plaintext = unhexlify('33B3DC87EDDD9B0F6A1F407D14919365'*3)
	>>> cipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
	>>> ciphertext = cipher.encrypt(plaintext)
	>>> decipher = python_Serpent.new(key,python_Serpent.MODE_CBC,IV)
	>>> hexlify( decipher.decrypt(ciphertext)).upper()
	'33B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D1491936533B3DC87EDDD9B0F6A1F407D14919365'
	"""
	return python_Serpent(key,mode,IV,counter)

class python_Serpent(blockcipher.BlockCipher):
	#need test vectors for other modes than ecb	
	def __init__(self,key,mode,IV,counter):
		self.cipher = Serpent(key)
		self.blocksize = self.cipher.get_block_size()
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
