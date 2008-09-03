import util
from array import array
import struct

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

class BlockCipher():
	""" Base class for all blockciphers
	"""

	def __init__(self,key,mode,IV,counter):
		self.key = key
		self.mode = mode
		self.cache = ''
		if mode == MODE_ECB:
			self.chain = ECB(self.blocksize)
		elif mode == MODE_CBC:
			self.chain = CBC(self.blocksize,IV)
		elif mode == MODE_CTR:
			assert counter != None
			self.chain = CTR(self.blocksize,counter)
		elif mode == MODE_XTS:
			self.chain = XTS()
		elif mode == MODE_CMAC:
			self.chain = CMAC(self.cipher,self.blocksize)

	def encrypt(self,plaintext):
		if self.mode == MODE_XTS:
			return self.chain.update(plaintext,'e',self.cipher,self.cipher2)
		else:
			return self.chain.update(plaintext,'e',self.cipher)
	
	def decrypt(self,ciphertext):
		if self.mode == MODE_XTS:
			return self.chain.update(ciphertext,'d',self.cipher,self.cipher2)
		else:
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
				self.IV = codebook.encrypt(util.xorstring(self.cache[i:i+self.blocksize],self.IV))
				encrypted_blocks.append(self.IV)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(encrypted_blocks)
		else:
			decrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
					plaintext = util.xorstring(self.IV,codebook.decrypt(self.cache[i:i + self.blocksize]))
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
	def __init__(self, blocksize, counter):
		self.counter = counter
		self.cache = ''
		self.blocksize = blocksize
		self.pos = 0

	def update(self, data,ed,codebook):
		# fancier version of CTR mode might have to deal with different
		# endianness options for the counter, etc.
        	n = len(data)
        	blocksize = self.blocksize
        	keystream = None
        	output = array('B', data)

        	for i in xrange(n):
			if not keystream:
				xpos = self.pos + i
				block = codebook.encrypt(self.counter())
				keystream = array('B', block[xpos % blocksize:])
			output[i] ^= keystream.pop(0)
        	self.pos += n
        	return output.tostring()

	def finish(self):
		pass

class XTS:
	def __init__(self):
		self.cache = ''

	def update(self, data, ed, codebook, codebook2):
		"""Perform a XTS encrypt/decrypt operation."""

		self.cache += data
		output = ''

		for i in xrange(len(self.cache) // 16):
    			# e_k2_n = E_K2(n)
	    		# was: n_txt = struct.pack('< Q', n) + '\x00' * 8
    			e_k2_n = codebook2.encrypt('\x00' * 16)[::-1]
			
    			# a_i = (a pow i)
    			a_i = util.gf2pow128powof2(i)
			
    			# e_mul_a = E_K2(n) mul (a pow i)
    			e_mul_a = util.gf2pow128mul(util.string2number(e_k2_n), a_i)
    			e_mul_a = util.number2string(e_mul_a)[::-1]
    			e_mul_a = '\x00' * (16 - len(e_mul_a)) + e_mul_a
			
    			# C = E_K1(P xor e_mul_a) xor e_mul_a
			if ed == 'd':
		    		output += util.xorstring16(e_mul_a, codebook.decrypt(util.xorstring16(e_mul_a, self.cache[i*16:(i+1)*16])))
			else:
				output += util.xorstring16(e_mul_a, codebook.encrypt(util.xorstring16(e_mul_a, self.cache[i*16:(i+1)*16])))
		
		self.cache = self.cache[(i+1)*16:]
		return output

	def finish(self):
		pass

class CMAC:
	"""CMAC chaining mode

	Supports every cipher with a blocksize available in de Rb_dictionary.
	Calling update(), immediately calculates the hash. No finishing needed.
	"""
	def __init__(self,codebook,blocksize):
		#blocksize (in bytes): to select the Rb constant in the dictionary
		#Rb as a dictionary: adding support for other blocksizes is easy
		self.cache=''
		self.blocksize = blocksize
		
		Rb_dictionary = {64:0x000000000000001b,128:0x00000000000000000000000000000087}
		self.Rb = Rb_dictionary[blocksize*8]

		mask1 = int(('\xff'*blocksize).encode('hex'),16)
		mask2 = int(('\x80' + '\x00'*(blocksize-1) ).encode('hex'),16)
		
		L = int(codebook.encrypt('\x00'*blocksize).encode('hex'),16)
		
		if L & mask2:
            		Lu = ((L << 1) & mask1) ^ self.Rb
		else:
		        Lu = L << 1
		        Lu = Lu & mask1
		 
	       	if Lu & mask2:
	            Lu2 = ((Lu << 1) & mask1)^ self.Rb
               	else:
	            Lu2 = Lu << 1
		    Lu2 = Lu2 & mask1

		self.Lu =Lu
		self.Lu2=Lu2
		
	def update(self,data,ed,codebook):
		assert ed == 'e'
		blocksize = self.blocksize
	
		m = (len(data)+blocksize-1)/blocksize #m = amount of datablocks
		y = '\x00'*blocksize
		i=0
		for i in range(1,m):
			y = codebook.encrypt( util.xorstring(data[(i-1)*blocksize:(i)*blocksize],y) )
		
		if len(data[(i)*blocksize:])==blocksize:
			Lu_string = util.number2string(self.Lu)
			X = util.xorstring(util.xorstring(data[(i)*blocksize:],y),Lu_string)
		else:
			tmp = data[(i)*blocksize:] + '\x80' + '\x00'*(blocksize - len(data[(i)*blocksize:])-1) 
			Lu2_string = util.number2string(self.Lu2)
			#Lu2_string = '\x00'*(blocksize - len(Lu2_string)) + Lu2_string
			X = util.xorstring(util.xorstring(tmp,y),Lu2_string)

		T = codebook.encrypt(X)
		return T

	def finish(self):
		pass

