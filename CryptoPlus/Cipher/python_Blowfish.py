# source of the used python implementation of blowfish
#	http://www.michaelgilfix.com/files/blowfish.py
# other possibility:
#	http://www.4dsolutions.net/cgi-bin/py2html.cgi?script=/ocn/python/blowfish.py
#		=> difficulties: doesn't define a class, only functions
#				 

import blockcipher
from pyblowfish import Blowfish

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	"""Create a new cipher object

	Wrapper for pure python implementation pyblowfish.py

	EXAMPLE: (http://www.schneier.com/code/vectors.txt)
	----------
	>>> import python_Blowfish
	>>> from binascii import hexlify, unhexlify
	>>> cipher = python_Blowfish.new(unhexlify('0131D9619DC1376E'))
	>>> hexlify( cipher.encrypt(unhexlify('5CD54CA83DEF57DA')) )
	'b1b8cc0b250f09a0'
	>>> hexlify( cipher.decrypt(unhexlify(_)) )
	'5cd54ca83def57da'

	Examples from: http://www.schneier.com/code/vectors.txt
	-------------------------------------------------------
	>>> key = '0123456789ABCDEFF0E1D2C3B4A59687'.decode('hex')
	>>> iv = 'FEDCBA9876543210'.decode('hex')
	>>> plaintext = '37363534333231204E6F77206973207468652074696D6520666F722000'.decode('hex')
	
	>>> cipher = python_Blowfish.new(key,python_Blowfish.MODE_CBC,iv)
	>>> ciphertext = cipher.encrypt(plaintext)
	>>> hexlify(ciphertext).upper()
	'6B77B4D63006DEE605B156E27403979358DEB9E7154616D9'

	>>> cipher = python_Blowfish.new(key,python_Blowfish.MODE_CFB,iv)
	>>> ciphertext = cipher.encrypt(plaintext)
	>>> hexlify(ciphertext).upper()
	'E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3'

	>>> cipher = python_Blowfish.new(key,python_Blowfish.MODE_OFB,iv)
	>>> ciphertext = cipher.encrypt(plaintext)
	>>> hexlify(ciphertext).upper()
	'E73214A2822139CA62B343CC5B65587310DD908D0C241B2263C2CF80DA'"""
	return python_Blowfish(key,mode,IV,counter)

class python_Blowfish(blockcipher.BlockCipher):
	def __init__(self,key,mode,IV,counter):
		self.cipher = Blowfish(key)
		self.blocksize = 8
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
