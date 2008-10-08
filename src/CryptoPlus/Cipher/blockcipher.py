from ..Util import util
from array import array
import struct
from ..Util.padding import Padding

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
        # Cipher classes inhereting from this one take care of:
        #   self.blocksize
        #   self.cipher
        self.key = key
        self.mode = mode
        self.cache = ''
        self.ed = None
        if mode == MODE_ECB:
            self.chain = ECB(self.cipher, self.blocksize)
        elif mode == MODE_CBC:
            assert IV <> None, "Provide an IV!"
            self.chain = CBC(self.cipher, self.blocksize,IV)
        elif mode == MODE_CFB:
            assert IV <> None, "Provide an IV!"
            self.chain = CFB(self.cipher, self.blocksize,IV)
        elif mode == MODE_OFB:
            assert IV <> None, "Provide an IV!"
            self.chain = OFB(self.cipher, self.blocksize,IV)
        elif mode == MODE_CTR:
            assert counter != None
            self.chain = CTR(self.cipher,self.blocksize,counter)
        elif mode == MODE_XTS:
            assert self.blocksize == 16
            self.chain = XTS(self.cipher, self.cipher2)
        elif mode == MODE_CMAC:
            assert self.blocksize in (8,16)
            self.chain = CMAC(self.cipher,self.blocksize)

    def encrypt(self,plaintext,n=''):
        """Encrypt some plaintext

        encrypt(plaintext,n='')
            plaintext   = a string of binary data
            n           = the 'tweak' value when the chaining mode is XTS

        The encrypt function will encrypt the supplied plaintext. When the supplied plaintext is not a multiple of the blocksize of the cipher,
        then the remaining plaintext will be cached. The next time the encrypt function is called with some plaintext, the new plaintext will be concatenated
        to the cache and then cache+plaintext will be encrypted.

        When the chaining mode allows the cipher to act as a stream cipher (CFB, OFB, CTR), the encrypt function will always encrypt all of the
        supplied plaintext immediately. No cache will be kept.

        For XTS the behavious is somewhat different: it needs the whole block of plaintext to be supplied at once. Every encrypt function called on a XTS cipher
        will output an encrypted block based on the current supplied plaintext block.
        """
        #self.ed = 'e' if chain is encrypting, 'd' if decrypting, None if nothing happened with the chain yet
        #assert self.ed in ('e',None) # makes sure you don't encrypt with a cipher that has started decrypting
        self.ed = 'e'
        if self.mode == MODE_XTS:
            # data sequence number (or 'tweak') has to be provided when in XTS mode
            return self.chain.update(plaintext,'e',n)
        else:
            return self.chain.update(plaintext,'e')

    def decrypt(self,ciphertext,n=''):
        """Decrypt some ciphertext

        decrypt(plaintext,n='')
            ciphertext  = a string of binary data
            n           = the 'tweak' value when the chaining mode is XTS

        The decrypt function will decrypt the supplied ciphertext. When the supplied ciphertext is not a multiple of the blocksize of the cipher,
        then the remaining ciphertext will be cached. The next time the decrypt function is called with some ciphertext, the new ciphertext will be concatenated
        to the cache and then cache+ciphertext will be decrypted.

        When the chaining mode allows the cipher to act as a stream cipher (CFB, OFB, CTR), the decrypt function will always decrypt all of the
        supplied ciphertext immediately. No cache will be kept.

        For XTS the behavious is somewhat different: it needs the whole block of ciphertext to be supplied at once. Every decrypt function called on a XTS cipher
        will output an decrypted block based on the current supplied ciphertext block.
        """
        #self.ed = 'e' if chain is encrypting, 'd' if decrypting, None if nothing happened with the chain yet
        #assert self.ed in ('d',None) # makes sure you don't decrypt with a cipher that has started encrypting
        self.ed = 'd'
        if self.mode == MODE_XTS:
            # data sequence number (or 'tweak') has to be provided when in XTS mode
            return self.chain.update(ciphertext,'d',n)
        else:
            return self.chain.update(ciphertext,'d')

    def final(self,padding='PKCS7'):
        # TODO: after calling final, reset the IV? so the cipher is as good as new?
        """finalizes the chain by padding

        final(padding='PKCS7'):
            padding = padding function provided as an argument. Possible padding functions:
                    - 'zerosPadding'
                    - 'bitPadding'
                    - 'PKCS7'
                    - 'ANSI_X923'
                    - 'ISO_10126'

        While a cipher object is in encryption mode, the final function will pad the remaining cache and encrypt it.
        If the cipher has been used for decryption, the final function won't do antyhing. You have to manually unpad if necessary or
        construct a Padder yourself en use its unpad function.

        After finalization, the chain can still be used but the IV, counter etc aren't reset but just continu as they were after the last step (finalization step).
        """
        assert self.mode not in (MODE_XTS, MODE_CMAC) # finalizing (=padding) doesn't make sense when in XTS or CMAC mode
        if self.ed == 'e':
            # when the chain is in encryption mode, finalizing will pad the cache and encrypt this last block
            padder = Padding(self.blocksize)
            if self.mode in (MODE_OFB,MODE_CFB,MODE_CTR):
                dummy = '0'*(self.blocksize - self.chain.keystream.buffer_info()[1]) # a dummy string that will be used to get a valid padding
            else: #ECB, CBC
                dummy = self.chain.cache
            return self.chain.update(padder.pad(dummy,padding)[len(dummy):],'e') # pad the cache and then only supply the padding to the update function
        else:
            # final function doesn't make sense when decrypting => padding should be removed manually
            pass

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
            #the only difference between encryption/decryption in the chain is the cipher block
            if ed == 'e':
                output_blocks.append(self.codebook.encrypt( self.cache[i:i + self.blocksize] ))
            else:
                output_blocks.append(self.codebook.decrypt( self.cache[i:i + self.blocksize] ))
        self.cache = self.cache[i+self.blocksize:]
        return ''.join(output_blocks)

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

class CTR:
    """CTR Mode

    Implemented so it can be accessed as a stream cipher.
    """
    # initial counter value can be choosen, decryption always starts from beginning
    #   -> you can start from anywhere yourself: just feed the cipher encoded blocks and feed a counter with the corresponding value
    def __init__(self, codebook, blocksize, counter):
        self.codebook = codebook
        self.counter = counter
        self.blocksize = blocksize
        self.keystream =array('B', '') #holds the output of the current encrypted counter value

    def update(self, data,ed):
        # no need for the encryption/decryption distinction: both are the same
        n = len(data)
        blocksize = self.blocksize

        output = array('B', data)
        for i in xrange(n):
            if self.keystream.buffer_info()[1] == 0: #encrypt a new counter block when the current keystream is fully used
                block = self.codebook.encrypt(self.counter())
                self.keystream = array('B', block)
            output[i] ^= self.keystream.pop(0) #as long as an encrypted counter value is available, the output is just "input XOR keystream"
        return output.tostring()

class XTS:
    # TODO: allow other blocksizes besides 16bytes?
    def __init__(self,codebook1, codebook2):
        self.cache = ''
        self.codebook1 = codebook1
        self.codebook2 = codebook2

    def update(self, data, ed,tweak=''):
        # supply n as a raw string
        # tweak = data sequence number
        """Perform a XTS encrypt/decrypt operation.

        In contrast to the other chaining modes: the whole data block has to encrypted at once."""

        output = ''
        assert len(data) > 15, "At least one block of 128 bits needs to be supplied"
        assert len(data) < 128*pow(2,20)

        i=0
        while i < ((len(data) // 16)-1): #Decrypt all the blocks but one last full block and opt one last partial block
            output += self.__xts_step(ed,data[i*16:(i+1)*16],i,tweak)
            i+=1
        # Check if the data supplied is a multiple of 16 bytes -> one last full block and we're done
        if len(data[i*16:]) == 16:
            output += self.__xts_step(ed,data[i*16:(i+1)*16],i,tweak)
        else:
            if ed=='e':
                (x, y) = (i, i+1)
            else: # Permutation of the last two indexes
                (x, y) = (i+1, i)
            # Decrypt/Encrypt the last two blocks when data is not a multiple of 16 bytes
            Cm1 = data[i*16:(i+1)*16]
            Cm = data[(i+1)*16:]
            PP = self.__xts_step(ed,Cm1,x,tweak)
            Cp = PP[len(Cm):]
            Pm = PP[:len(Cm)]
            CC = Cm+Cp
            Pm1 = self.__xts_step(ed,CC,y,tweak)
            output += Pm1 + Pm
        return output

    def __xts_step(self,ed,tocrypt,i,tweak):
        # based on the pseudo code in the P1619 standard
        # pseudo: the tweak is kept as the shifted version after every xts-step
        # here:   the tweak is supplied as the clean value every step => while loop to simulate
        #         previous steps

        # e_k2_n = E_K2(tweak)
        e_k2_n = self.codebook2.encrypt(tweak+ '\x00' * (16-len(tweak)))[::-1]

        # T = E_K2(n) mul (a pow i)
        T = util.string2number(e_k2_n)
        while i:
            T = T << 1
            # if (Cout)
            if T >> (8*16):
                #T[0] ^= GF_128_FDBK;
                T = T ^ 0x100000000000000000000000000000087L
            i-=1
        T = util.number2string_N(T, 16)[::-1]

        # C = E_K1(P xor T) xor T
        if ed == 'd':
            return util.xorstring(T, self.codebook1.decrypt(util.xorstring(T, tocrypt)))
        else:
            return util.xorstring(T, self.codebook1.encrypt(util.xorstring(T, tocrypt)))

class CMAC:
    """CMAC chaining mode

    Supports every cipher with a blocksize available in de Rb_dictionary.
    Calling update(), immediately calculates the hash. No finalizing needed.
    The hashlenght is equal to block size of the used block cipher
    """
    # TODO: move to hash module?
    # TODO: change update behaviour to .update() and .digest() as for all hash modules?
    #       -> other hash functions in pycrypto: calling update, concatenates current input with previous input and hashes everything
    def __init__(self,codebook,blocksize):
        # Purpose of init: calculate Lu & Lu2
        #blocksize (in bytes): to select the Rb constant in the dictionary
        #Rb as a dictionary: adding support for other blocksizes is easy
        self.cache=''
        self.blocksize = blocksize
        self.codebook = codebook

        #Rb_dictionary: holds values for Rb for different blocksizes
        # values for 64 and 128 bits found here: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
        # explanation from: http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
        #             Rb is a representation of a certain irreducible binary polynomial of degree b, namely,
        #             the lexicographically first among all such polynomials with the minimum possible number of
        #             nonzero terms. If this polynomial is expressed as ub+cb-1ub-1+...+c2u2+c1u+c0, where the
        #             coefficients cb-1, cb-2, ..., c2, c1, c0 are either 0 or 1, then Rb is the bit string cb-1cb-2...c2c1c0.

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
        return T
