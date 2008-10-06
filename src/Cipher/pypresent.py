# fully based on standard specifications: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/present_ches2007.pdf
# test vectors: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/slides/present_testvectors.zip

class Present:

        def __init__(self,key,rounds=32):
                """Generating roundkeys

                When a Present class initialized, the roundkeys will be generated.
                You can supply the key as a 128bit or 80bit rawstring.
                """
                self.rounds = rounds
                self.key = key.encode('hex')
                if len(self.key) == 80/4:
                        self.roundkeys = generateRoundkeys80(self.key,self.rounds)
                elif len(self.key) == 128/4:
                        self.roundkeys = generateRoundkeys128(self.key,self.rounds)
                else:
                        pass

        def encrypt(self,block):
                """Encrypting 1 block (8 bytes)

                Supply the plaintext block as a raw string and the raw
                ciphertext will be returned.
                """
                state = block.encode('hex')
                for i in range (1,self.rounds):
                        state = addRoundKey(state,self.roundkeys[i-1])
                        state = sBoxLayer(state)
                        state = pLayer(state)
                cipher = addRoundKey(state,self.roundkeys[self.rounds-1])
                return cipher.decode('hex')

        def decrypt(self,block):
                """Decrypting 1 block (8 bytes)

                Supply the ciphertext block as a raw string and the raw
                plaintext will be returned.
                """
                state = block.encode('hex')
                for i in range (1,self.rounds):
                        state = addRoundKey(state,self.roundkeys[self.rounds-i])
                        state = pLayer_dec(state)
                        state = sBoxLayer_dec(state)
                decipher = addRoundKey(state,self.roundkeys[0])
                return decipher.decode('hex')

        def get_block_size(self):
                return 8

#        0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
SBox = ['c','5','6','b','9','0','a','d','3','e','f','8','4','7','1','2']
PBox = [0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
        4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
        8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
        12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]

def generateRoundkeys80(key,rounds):
        """Generate the roundkeys for a 80 bit key

        Give a 80bit hex string as input and get a list of roundkeys in return"""
        roundkeys = []
        for i in range(1,rounds+1): # (K0 ... K32)
                # rawKey[0:63]
                roundkeys.append(("%x" % (int(key,16) >>16 )).zfill(64/4))
                #1. Shift
                #rawKey[19:(len(rawKey)-1)]+rawKey[0:18]
                key = ("%x" % ( ((int(key,16) & (pow(2,19)-1)) << 61) + (int(key,16) >> 19))).zfill(80/4)
                #2. SBox
                #rawKey[76:79] = S(rawKey[76:79])
                key = SBox[int(key[0],16)]+key[1:20]
                #3. Salt
                #rawKey[15:19] ^ i
                temp = (int(key,16) >> 15)
                temp = temp ^ i
                key = ( int(key,16) & (pow(2,15)-1) ) + (temp << 15)
                key = ("%x" % key).zfill(80/4)
        return roundkeys

def generateRoundkeys128(key,rounds):
        """Generate the roundkeys for a 128 bit key

        Give a 128bit hex string as input and get a list of roundkeys in return"""
        roundkeys = []
        for i in range(1,rounds+1): # (K0 ... K32)
                roundkeys.append(("%x" % (int(key,16) >>64)).zfill(64/4))
                #1. Shift
                key = ("%x" % ( ((int(key,16) & (pow(2,67)-1)) << 61) + (int(key,16) >> 67))).zfill(128/4)
                #2. SBox
                key = SBox[int(key[0],16)]+SBox[int(key[1],16)]+key[2:]
                #3. Salt
                #rawKey[15:19] ^ i
                temp = (int(key,16) >> 62)
                temp = temp ^ (i%32)
                key = ( int(key,16) & (pow(2,62)-1) ) + (temp << 62)
                key = ("%x" % key).zfill(128/4)
        return roundkeys

def addRoundKey(state,roundkey):
        return ( "%x" % ( int(state,16) ^ int(roundkey,16) ) ).zfill(16)

def sBoxLayer(state):
        """SBox function for encryption

        Takes a hex string as input and will output a hex string"""
        output =''
        for i in range(len(state)):
                output += SBox[int(state[i],16)]
        return output

def sBoxLayer_dec(state):
        """Inverse SBox function for decryption

        Takes a hex string as input and will output a hex string"""
        output =''
        for i in range(len(state)):
                output += hex( SBox.index(state[i]) )[2:]
        return output

def pLayer(state):
        """Permutation layer for encryption

        Takes a 64bit hex string as input and will output a 64bit hex string"""
        output = ''
        state_bin = bin(int(state,16)).zfill(64)[::-1][0:64]
        for i in range(64):
                output += state_bin[PBox.index(i)]
        return ("%x" % int(output[::-1],2)).zfill(16)

def pLayer_dec(state):
        """Permutation layer for decryption

        Takes a 64bit hex string as input and will output a 64bit hex string"""
        output = ''
        state_bin = bin(int(state,16)).zfill(64)[::-1][0:64]
        for i in range(64):
                output += state_bin[PBox[i]]
        return ("%x" % int(output[::-1],2)).zfill(16)

def bin(a):
        """Convert an integer to a bin string (1 char represents 1 bit)"""
        #http://wiki.python.org/moin/BitManipulation
        s=''
        t={'0':'000','1':'001','2':'010','3':'011','4':'100','5':'101','6':'110','7':'111'}
        for c in oct(a).rstrip('L')[1:]:
                s+=t[c]
        return s
