import blockcipher
import pyDes

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	return python_DES3(key,mode,IV,counter)

class python_DES3(blockcipher.BlockCipher):
	"""wrapper for pure python 3DES implementation pyDes.py

	EXAMPLE (using test vectors from http://csrc.nist.gov/groups/STM/cavp/documents/des/DESMMT.pdf):
	>>> import python_DES3	
	>>> from binascii import hexlify, unhexlify
	>>> key = unhexlify('37ae5ebf46dff2dc0754b94f31cbb3855e7fd36dc870bfae')
	>>> IV = unhexlify('3d1de3cc132e3b65')
	>>> cipher = python_DES3.new(key, python_DES3.MODE_CBC, IV)
	>>> ciphertext = cipher.encrypt(unhexlify('84401f78fe6c10876d8ea23094ea5309'))
	>>> hexlify(ciphertext)
	'7b1f7c7e3b1c948ebd04a75ffba7d2f5'
	>>> decipher = python_DES3.new(key, python_DES3.MODE_CBC, IV)
	>>> plaintext = decipher.decrypt(ciphertext)
	>>> hexlify(plaintext)
	'84401f78fe6c10876d8ea23094ea5309'

	CMAC EXAMPLE:
	-------------
	testvector: http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf

	>>> key = '8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5'.decode('hex')
	>>> plaintext = '6bc1bee22e409f96e93d7e117393172aae2d8a57'.decode('hex')
	>>> cipher = python_DES3.new(key, python_DES3.MODE_CMAC)
	>>> cipher.encrypt(plaintext).encode('hex')
	'743ddbe0ce2dc2ed'
	"""
	def __init__(self,key,mode,IV,counter):
		self.cipher = pyDes.triple_des(key)
		self.blocksize = self.cipher.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
