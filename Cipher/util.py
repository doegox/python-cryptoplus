def xor(str1,str2):
		#move this to a math module
		outlist = []
		for k in range(len(str1)):
			outlist += [chr( ord(str1[k])^ord(str2[k]) )]
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
