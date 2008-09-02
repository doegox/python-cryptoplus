from gf2n import *

def long2string(i):
    s=hex(i)[2:-1]
    if len(s) % 2:
        s='0'+s
    return s.decode('hex')

def xorstring(a,b):
	outlist = []
	minlength = min(len(a),len(b))
	if minlength == len(a):
		maxstr = b
		minstr = a
	else:
		maxstr = a
		minstr = b	
	for k in range(len(minstr)):
		outlist += [chr( ord(a[k])^ord(b[k]) )]
	for i in maxstr[len(minstr):]:
		outlist += i
	return ''.join(outlist)

class Counter(str):
	#found here: http://www.lag.net/pipermail/paramiko/2008-February.txt
	"""Necessary for CTR chaining mode
	
	Initializing a counter object (ctr = Counter('xxx'), gives a value to the counter object.
	Everytime the object is called ( ctr() ) it returns the current value and increments it by 1.
	Input/output is a raw string.
	"""
        def __init__(self, initial_ctr):
            if not isinstance(initial_ctr, str):
                raise TypeError("nonce must be str")
            self.c = int(initial_ctr.encode('hex'), 16)
        def __call__(self):
            # This might be slow, but it works as a demonstration
            ctr = ("%032x" % (self.c,)).decode('hex')
            self.c += 1
            return ctr

## Following code is from XTS.py => add appropriate copyright notice?

def str2int(str):
	N = 0
	for c in reversed(str):
    		N <<= 8
    	        N |= ord(c)
    	return N
	
def int2str(N):
	str = ''
    	while N:
    		str += chr(N & 0xff)
    		N >>= 8
    	return str
		
def xorstring16(a, b):
 	new = ''
    	for p in xrange(16):
    		new += chr(ord(a[p]) ^ ord(b[p]))
    	return new

def gf2pow128powof2(n):
	"""2^n in GF(2^128)."""
	if n < 128:
	        return 2**n
	return reduce(gf2pow128mul, (2 for x in xrange(n)), 1)

## end of code from XTS.py
