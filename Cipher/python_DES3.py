import blockcipher
import pyDes

def new(key,mode=blockcipher.MODE_ECB,IV=None):
	return python_DES3(key,mode,IV)

class python_DES3(blockcipher.BlockCipher):
	"""wrapper for pure python 3DES implementation pyDes.py
	"""
	def __init__(self,key,mode,IV):
		self.cipher = pyDes.triple_des(self.key)
		self.blocksize = self.cipher.block_size
		blockcipher.BlockCipher.__init__(self,key,mode,IV)

def _test():
	import doctest
	doctest.testmod()

if __name__ == "__main__":
	_test()
