import util
from array import array
import struct
from padding import Padding

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
		self.ed = None
		if mode == MODE_ECB:
			self.chain = ECB(self.cipher, self.blocksize)
		elif mode == MODE_CBC:
			self.chain = CBC(self.cipher, self.blocksize,IV)
		elif mode == MODE_CFB:
			self.chain = CFB(self.cipher, self.blocksize,IV)
		elif mode == MODE_OFB:
			self.chain = OFB(self.cipher, self.blocksize,IV)
		elif mode == MODE_CTR:
			assert counter != None
			self.chain = CTR(self.cipher,self.blocksize,counter)
		elif mode == MODE_XTS:
			self.chain = XTS(self.cipher, self.cipher2)
		elif mode == MODE_CMAC:
			self.chain = CMAC(self.cipher,self.blocksize)

	def encrypt(self,plaintext,n=''):
		assert self.ed in ('e',None) # makes sure you don't encrypt with a cipher that has started decrypting
		self.ed = 'e'
		if self.mode == MODE_XTS:
			return self.chain.update(plaintext,'e',n)
		else:
			return self.chain.update(plaintext,'e')
	
	def decrypt(self,ciphertext,n=''):
		assert self.ed in ('d',None) # makes sure you don't decrypt with a cipher that has started encrypting
		self.ed = 'd'
		if self.mode == MODE_XTS:
			return self.chain.update(ciphertext,'d',n)
		else:
			return self.chain.update(ciphertext,'d')
	
	def final(self,data=''):
		return self.chain.final(data,self.ed)

class ECB:
	def __init__(self, codebook, blocksize):
		self.cache = ''
		self.codebook = codebook
		self.blocksize = blocksize

	def update(self, plaintext,ed):
		"""update the chain
		
		ed = 'e' or 'd' = encrypt or decrypt => encrypt() or decrypt() from BlockCipher will pass the right one
		codebook = encrypt/decrypt will pass "self.cipher.encrypt()" or "decrypt()"
		"""
		output_blocks = []
		self.cache += plaintext
		if len(self.cache) < self.blocksize:
			return ''
		for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
			#the only difference between encryption/decryption is the cipher block
			if ed == 'e':
				output_blocks.append(self.codebook.encrypt( self.cache[i:i + self.blocksize] ))
			else:
				output_blocks.append(self.codebook.decrypt( self.cache[i:i + self.blocksize] ))
		self.cache = self.cache[i+self.blocksize:]
		return ''.join(output_blocks)

	def final(self):
		"""finalizes the chain by padding

		padding function can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		assert ed <> None
		output = ''
		if ed == 'e':
			padder = Padding(self.blocksize)
			output += self.update(data,ed)
			output += self.update(padder.pad(self.cache,padding)[len(self.cache):],ed)
		return output

class CBC:
	def __init__(self, codebook, blocksize, IV):
		self.IV = IV
		self.cache = ''
		self.codebook = codebook
		self.blocksize = blocksize

	def update(self, input,ed):
		"""update the chain
		
		"""
		if ed == 'e':
			encrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
				self.IV = self.codebook.encrypt(util.xorstring(self.cache[i:i+self.blocksize],self.IV))
				encrypted_blocks.append(self.IV)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(encrypted_blocks)
		else:
			decrypted_blocks = []
			self.cache += input
			if len(self.cache) < self.blocksize:
				return ''
			for i in range(0, len(self.cache)-self.blocksize+1, self.blocksize):
					plaintext = util.xorstring(self.IV,self.codebook.decrypt(self.cache[i:i + self.blocksize]))
					self.IV = self.cache[i:i + self.blocksize]
					decrypted_blocks.append(plaintext)
			self.cache = self.cache[i+self.blocksize:]
			return ''.join(decrypted_blocks)
				

	def final(self,data,ed,padding='PKCS7'):
		"""finalizes the chain by padding

		padding codebooktion can be provided as an argument
		no way to finalize with standart pycrypto API
			=> finalize when submitted plaintext or ciphertext == '' ?
		"""
		assert ed <> None
		output = ''
		if ed == 'e':
			padder = Padding(self.blocksize)
			output += self.update(data,ed)
			output += self.update(padder.pad(self.cache,padding)[len(self.cache):],ed)
		return output
			

class CFB:
	"""CFB Chaining Mode

	Can be accessed as a stream cipher. Input to the chain must be a multiple of bytes."""
	def __init__(self, codebook, blocksize, IV):
		self.codebook = codebook
		self.IV = IV
		self.blocksize = blocksize
		self.keystream =array('B', '')
	def update(self, data,ed):
		n = len(data)
        	blocksize = self.blocksize
        	output = array('B', data)

        	for i in xrange(n):
			if ed =='e':
				if self.keystream.buffer_info()[1] == 0: 
					block = self.codebook.encrypt(self.IV)
					self.keystream = array('B', block)
					self.IV = ''
				output[i] ^= self.keystream.pop(0)
				self.IV += chr(output[i]) # the IV for the next block in the chain is being built byte per byte as the ciphertext flows in
			else:
				if self.keystream.buffer_info()[1] == 0:
					block = self.codebook.encrypt(self.IV)
					self.keystream = array('B', block)
					self.IV = ''
				self.IV += chr(output[i]) 
				output[i] ^= self.keystream.pop(0)
        	return output.tostring()

	def final(self):
		pass

class OFB:
	"""OFB Chaining Mode

	Can be accessed as a stream cipher. Input to the chain must be a multiple of bytes."""
	def __init__(self, codebook, blocksize, IV):
		self.codebook = codebook
		self.IV = IV
		self.blocksize = blocksize
		self.keystream =array('B', '')
	def update(self, data,ed):
		#no difference between encryption and decryption mode
		n = len(data)
        	blocksize = self.blocksize
        	output = array('B', data)

        	for i in xrange(n):
			if self.keystream.buffer_info()[1] == 0: #encrypt a new counter block when the current keystream is fully used
				self.IV = self.codebook.encrypt(self.IV)
				self.keystream = array('B', self.IV)
			output[i] ^= self.keystream.pop(0) #as long as an encrypted counter value is available, the output is just "input XOR keystream"
        	return output.tostring()

	def final(self):
		""" finalize the cipher
		
		Dummy function: cipher can be accessed as a stream cipher => no need for padding at the end"""
		pass


class CTR:
	"""CTR Mode

	Implemented so it can be accessed as a stream cipher.
	"""
	# other implementation: counter always starts from zero but can decode starting from anywhere by giving a position
	# this implementation: initial counter value can be choosen, decryption always starts from beginning
	def __init__(self, codebook, blocksize, counter):
		self.codebook = codebook
		self.counter = counter
		self.blocksize = blocksize
		self.keystream =array('B', '') #holds the output of the current encrypted counter value

	def update(self, data,ed):
		# no need for the encryption/decryption distinction: both are the same
		# fancier version of CTR mode might have to deal with different
		# endianness options for the counter, etc.
        	n = len(data)
        	blocksize = self.blocksize
       
        	output = array('B', data)
        	for i in xrange(n):
			if self.keystream.buffer_info()[1] == 0: #encrypt a new counter block when the current keystream is fully used
				block = self.codebook.encrypt(self.counter())
				self.keystream = array('B', block)
			output[i] ^= self.keystream.pop(0) #as long as an encrypted counter value is available, the output is just "input XOR keystream"
        	return output.tostring()

	def final(self):
		""" finalize the cipher
		
		Dummy function: cipher can be accessed as a stream cipher => no need for padding at the end"""
		pass

class XTS:
	# TODO: allow other blocksizes besides 16bytes (= AES)
	def __init__(self,codebook1, codebook2):
		self.cache = ''
		self.codebook1 = codebook1
		self.codebook2 = codebook2

	def update(self, data, ed,n=''):
		# supply n as a raw string
		# n = data sequence number
		"""Perform a XTS encrypt/decrypt operation.

		In contrast to the other chaining modes: the whole data block has to encrypted at once."""

		output = ''
		assert len(data) > 15

		def xts_step(tocrypt):
			# e_k2_n = E_K2(n)
	    		# was: n_txt = struct.pack('< Q', n) + '\x00' * 8
			n_number = util.string2number(n.rjust(1,'\x00'))
			e_k2_n = self.codebook2.encrypt(struct.pack('< Q', n_number)+ '\x00' * 8)[::-1]

    			# a_i = (a pow i)
    			a_i = util.gf2pow128powof2(i)
			
    			# e_mul_a = E_K2(n) mul (a pow i)
    			e_mul_a = util.gf2pow128mul(util.string2number(e_k2_n), a_i)
    			e_mul_a = util.number2string(e_mul_a)[::-1]
    			e_mul_a = '\x00' * (16 - len(e_mul_a)) + e_mul_a
			
    			# C = E_K1(P xor e_mul_a) xor e_mul_a
			if ed == 'd':
		    		return util.xorstring16(e_mul_a, self.codebook1.decrypt(util.xorstring16(e_mul_a, tocrypt)))
			else:
				return util.xorstring16(e_mul_a, self.codebook1.encrypt(util.xorstring16(e_mul_a, tocrypt)))

		i=0
		for i in xrange((len(data) // 16) - 1):
			output += xts_step(data[i*16:(i+1)*16])
		i+=1
		if len(data[i*16:]) == 16:
			output += xts_step(data[i*16:(i+1)*16])
		else:
			if i == 1 : i-=1 #no output blocks have been calculated yet => have to start from the beginning
			Pm1 = data[i*16:(i+1)*16]
			Pm = data[(i+1)*16:]
			CC = xts_step(Pm1)
			Cp = CC[len(Pm):]
			Cm = CC[:len(Pm)]
			PP = Pm+Cp
			i+=1
			Cm1 = xts_step(PP)
			output += Cm1 + Cm
    				
		return output

	def final(self):
		pass

class CMAC:
	"""CMAC chaining mode

	Supports every cipher with a blocksize available in de Rb_dictionary.
	Calling update(), immediately calculates the hash. No finaling needed.
	"""
	# TODO: move to hash module
	def __init__(self,codebook,blocksize):
		# Purpose of init: calculate Lu & Lu2
		#blocksize (in bytes): to select the Rb constant in the dictionary
		#Rb as a dictionary: adding support for other blocksizes is easy
		self.cache=''
		self.blocksize = blocksize
		self.codebook = codebook		

		Rb_dictionary = {64:0x000000000000001b,128:0x00000000000000000000000000000087}
		self.Rb = Rb_dictionary[blocksize*8]

		mask1 = int(('\xff'*blocksize).encode('hex'),16)
		mask2 = int(('\x80' + '\x00'*(blocksize-1) ).encode('hex'),16)
		
		L = int(self.codebook.encrypt('\x00'*blocksize).encode('hex'),16)
		
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
		
	def update(self,data,ed):
		# not really an update function: everytime the function is called, the hash from the input data is calculated
		# TODO: change update behaviour
		# TODO: add possibility for other hash lengths?
		# other hash functions in pycrypto: calling update, concatenates current input with previous input and hashes everything
		assert ed == 'e'
		blocksize = self.blocksize
	
		m = (len(data)+blocksize-1)/blocksize #m = amount of datablocks
		y = '\x00'*blocksize
		i=0
		for i in range(1,m):
			y = self.codebook.encrypt( util.xorstring(data[(i-1)*blocksize:(i)*blocksize],y) )
		
		if len(data[(i)*blocksize:])==blocksize:
			Lu_string = util.number2string(self.Lu)
			X = util.xorstring(util.xorstring(data[(i)*blocksize:],y),Lu_string)
		else:
			tmp = data[(i)*blocksize:] + '\x80' + '\x00'*(blocksize - len(data[(i)*blocksize:])-1) 
			Lu2_string = util.number2string(self.Lu2)
			#Lu2_string = '\x00'*(blocksize - len(Lu2_string)) + Lu2_string
			X = util.xorstring(util.xorstring(tmp,y),Lu2_string)

		T = self.codebook.encrypt(X)
		return T[:8]

	def final(self):
		pass

