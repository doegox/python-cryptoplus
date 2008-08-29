def xor(str1,str2):
		#move this to a math module
		outlist = []
		for k in range(len(str1)):
			outlist += [chr( ord(str1[k])^ord(str2[k]) )]
		return ''.join(outlist)
