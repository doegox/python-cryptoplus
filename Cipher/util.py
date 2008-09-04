from __future__ import division #http://www.python.org/dev/peps/pep-0238/
from gf2n import *
import math

def roundUp (n, p):
	"""Round an integer up to the nearest multiple

	A given integer n will be round up to the nearest multiple of p

	Example:
	>>> roundUp(13,8)
	    16
	"""
	return int(math.ceil(n/p)*p)

def number2string(i):
	"""Convert a number to a string
	    
	Input: long or integer
	Output: string (big-endian)
	"""
	s=hex(i)[2:].rstrip('L')
	if len(s) % 2:
		s = '0' + s
	return s.decode('hex')

def string2number(i):
	""" Convert a string to a number

	Input: string (big-endian)
	Output: long or integer
	"""
	return int(i.encode('hex'),16)

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
	Input/output is a raw string."""
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
