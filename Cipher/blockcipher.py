from util import xor
from array import array

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6

class BlockCipher():
	""" Base class for all blockciphers
	"""

	def __init__(self,key,mode,IV):
		self.key = key
		self.mode = mode
		self.cache = ''
		if mode == MODE_ECB:
			self.chain = ECB(self.blocksize)
		elif mode == MODE_CBC:
			self.chain = CBC(self.blocksize,IV)
		elif mode == MODE_CTR:
			self.chain = CTR(self.blocksize,IV)

	def encrypt(self,plaintext):
		return self.chain.update(plaintext,'e',self.cipher)
	
	def decrypt(self,ciphertext):
		return self.chain.update(ciphertext,'d',self.cipher)

class ECB:
	def __init__(self, blocksize):
		self.cache = ''
		self.blocksize = blocksize

	def update(self, plaintext,ed,codebook):
		"""update the chain
		
		ed = 'e' or 'd' = encrypt or decrypt => encrypt() or decrypt() from BlockCipher will pass the right one
		codebook = encrypt/decrypt will pass "self.cipher.encrypt()" or "decrypt()"
		"""
		output_blocks = []
		self.cache += plaintext
		if len(self.cache) < self.blocksize:
			return ''
		for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
			if ed == 'e':
				output_blocks.append(codebook.encrypt( self.cache[i:i + self.blocksize] ))
			else:
				output_blocks.append(codebook.decrypt( self.cache[i:i + self.blocksize] ))
		self.cache = self.cache[i+self.blocksize:]
		return ''.join(output_blocks)

	def finish(self):
		"""finalizes the chain by padding

		padding codebooktion can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		pass

class CBC:
	def __init__(self, blocksize, IV):
		self.IV = IV
		self.cache = ''
		self.blocksize = blocksize

	def update(self, input,ed,codebook):
		"""update the chain
		
		"""
		if ed == 'e':
			encrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
				self.IV = codebook.encrypt(xor(self.cache[i:i+self.blocksize],self.IV))
				encrypted_blocks.append(self.IV)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(encrypted_blocks)
		else:
			decrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
					plaintext = xor(self.IV,codebook.decrypt(self.cache[i:i + self.blocksize]))
					self.IV = self.cache[i:i + self.blocksize]
					decrypted_blocks.append(plaintext)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(decrypted_blocks)
				

	def finish(self):
		"""finalizes the chain by padding

		padding codebooktion can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		pass

class CTR:
	"""CTR Mode

	Implemented so it can be accessed as a stream cipher.
	"""
	#TODO:
	# mogelijkheid om slecht een aantal bytes van IV te gebruiken als counter
	def __init__(self, blocksize, IV):
		self.IV = IV
		self.cache = ''
		self.blocksize = blocksize
		self.pos = 0

	def update(self, data,ed,codebook):
	        from binascii import unhexlify,hexlify

		def long2string(i):
  		  s=hex(i)[2:-1]
		  if len(s) % 2:
		      s='0'+s
		  return unhexlify(s)

        	# fancier version of CTR mode might have to deal with different
        	# endianness options for the counter, etc.
        	n = len(data)
        	blocksize = self.blocksize
        	keystream = None
        	output = array('B', data)
	
        	for i in xrange(n):
        	    if not keystream:
        	        xpos = self.pos + i
        	        block = codebook.encrypt(self.IV)
        	        keystream = array('B', block[xpos % blocksize:])
			self.IV = long2string( (long(hexlify(self.IV),16)+1)%pow(2,(len(self.IV)*8)) )
        	    output[i] ^= keystream.pop(0)
        	self.pos += n
        	return output.tostring()

	def finish(self):
		pass

