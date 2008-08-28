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
		self.IV = IV
		self.cache = ''
		if mode == MODE_ECB:
			self.chain = ECB(self.blocksize)
		elif mode == MODE_CBC:
			self.chain = CBC(self.blocksize,IV)

	def encrypt(self,plaintext):
		return self.chain.update(plaintext,'e',self.cipher.encrypt)
	
	def decrypt(self,ciphertext):
		return self.chain.update(ciphertext,'d',self.cipher.decrypt)

class ECB:
	def __init__(self, blocksize):
		self.cache = ''
		self.blocksize = blocksize

	def update(self, plaintext,ed,func):
		"""update the chain
		
		ed = 'e' or 'd' = encrypt or decrypt => encrypt() or decrypt() from BlockCipher will pass the right one
		func = encrypt/decrypt will pass "self.cipher.encrypt()" or "decrypt()"
		"""
		output_blocks = []
		self.cache += plaintext
		if len(self.cache) < self.blocksize:
			return ''
		for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
			output_blocks.append(func( self.cache[i:i + self.blocksize] ))
		self.cache = self.cache[i+self.blocksize:]
		return ''.join(output_blocks)

	def finish(self):
		"""finalizes the chain by padding

		padding function can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		pass

	def __xor(self,str1,str2):
		#move this to a math module
		outlist = []
		for k in range(len(str1)):
			outlist += [chr( ord(str1[k])^ord(str2[k]) )]
		return ''.join(outlist)

class CBC:
	def __init__(self, blocksize, IV):
		self.IV = IV
		self.cache = ''
		self.blocksize = blocksize

	def update(self, input,ed,func):
		"""update the chain
		
		ed = 'e' or 'd' = encrypt or decrypt => encrypt() or decrypt() from BlockCipher will pass the right one
		func = encrypt/decrypt will pass "self.cipher.encrypt()" or "decrypt()"
		"""
		if ed == 'e':
			encrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
				self.IV = func(self.__xor(self.cache[i:i+self.blocksize],self.IV))
				encrypted_blocks.append(self.IV)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(encrypted_blocks)
		else:
			decrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
					plaintext = self.__xor(self.IV,func(self.cache[i:i + self.blocksize]))
					self.IV = self.cache[i:i + self.blocksize]
					decrypted_blocks.append(plaintext)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(decrypted_blocks)
				

	def finish(self):
		"""finalizes the chain by padding

		padding function can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		pass

	def __xor(self,str1,str2):
		#move this to a math module
		outlist = []
		for k in range(len(str1)):
			outlist += [chr( ord(str1[k])^ord(str2[k]) )]
		return ''.join(outlist)
