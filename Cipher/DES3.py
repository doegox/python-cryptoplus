import blockcipher
import Crypto.Cipher.DES3

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_CMAC = 8

def new(key,mode=blockcipher.MODE_ECB,IV=None,counter=None):
	return DES3(key,mode,IV,counter)

class DES3(blockcipher.BlockCipher):
	#need test vectors
	"""DES using pycrypto for algo en pycryptoplus for ciphermode

	Supply the 3 keys as 1 single concatenated key = key1|key2|key3
	
	EXAMPLE (using test vectors from http://csrc.nist.gov/groups/STM/cavp/documents/des/DESMMT.pdf):
	>>> import DES3	
	>>> from binascii import hexlify, unhexlify
	>>> key = unhexlify('37ae5ebf46dff2dc0754b94f31cbb3855e7fd36dc870bfae')
	>>> IV = unhexlify('3d1de3cc132e3b65')
	>>> cipher = DES3.new(key, DES3.MODE_CBC, IV)
	>>> ciphertext = cipher.encrypt(unhexlify('84401f78fe6c10876d8ea23094ea5309'))
	>>> hexlify(ciphertext)
	'7b1f7c7e3b1c948ebd04a75ffba7d2f5'
	>>> decipher = DES3.new(key, DES3.MODE_CBC, IV)
	>>> plaintext = decipher.decrypt(ciphertext)
	>>> hexlify(plaintext)
	'84401f78fe6c10876d8ea23094ea5309'

	CMAC EXAMPLE:
	-------------
	testvector: http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf

	>>> key = '8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5'.decode('hex')
	>>> plaintext = '6bc1bee22e409f96e93d7e117393172aae2d8a57'.decode('hex')
	>>> cipher = DES3.new(key, DES3.MODE_CMAC)
	>>> cipher.encrypt(plaintext).encode('hex')
	'743ddbe0ce2dc2ed'
	"""
	def __init__(self,key,mode,IV,counter):
		self.cipher = Crypto.Cipher.DES3.new(key)
		self.blocksize = Crypto.Cipher.DES3.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV,counter)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
