from tester_vectors import dict_cmac_aes128,dict_cmac_aes192,dict_cmac_aes256,dict_cmac_tdes2,dict_cmac_tdes3
from tester_vectors import dict_des,dict_tdes2,dict_tdes3
from tester_vectors import dict_serpent128,dict_serpent192,dict_serpent256

# DES,TDES2/3

from CryptoPlus.Cipher import python_DES

for i in range(0,len(dict_des)/3):
	msg = dict_des['msg%i'%i].decode('hex')
	key = dict_des['key%i'%i].decode('hex')
	cip = dict_des['cip%i'%i].decode('hex')
	cipher = python_DES.new(key,python_DES.MODE_ECB)
	if cip <> cipher.encrypt(msg):
		print 'ERROR! for DES in %i'%i

from CryptoPlus.Cipher import python_DES3

for dict in dict_tdes2,dict_tdes3:
	for i in range(0,len(dict)/3):
		msg = dict['msg%i'%i].decode('hex')
		key = dict['key%i'%i].decode('hex')
		cip = dict['cip%i'%i].decode('hex')
		cipher = python_DES3.new(key,python_DES3.MODE_ECB)
		if cip <> cipher.encrypt(msg):
			print 'ERROR! for TDES2/3 in %i'%i

# Serpent128/192/256

from CryptoPlus.Cipher import python_Serpent

for dict in dict_serpent128,dict_serpent192,dict_serpent256:
	for i in range(0,len(dict)/3):
		msg = dict['msg%i'%i].decode('hex')
		key = dict['key%i'%i].decode('hex')
		cip = dict['cip%i'%i].decode('hex')
		cipher = python_Serpent.new(key,python_Serpent.MODE_ECB)
		if cip <> cipher.encrypt(msg):
			print 'ERROR! for Serpent in %i'%i

# CMAC-AES128/192/256

from CryptoPlus.Cipher import python_AES

for dict in dict_cmac_aes128,dict_cmac_aes192,dict_cmac_aes256:
	for i in range(0,len(dict)/4):
		msg = dict['msg%i'%i].decode('hex')
		key = dict['key%i'%i].decode('hex')
		if msg == '\x00':
			msg = ''
		mac = dict['mac%i'%i].decode('hex')
		cipher = python_AES.new(key,python_AES.MODE_CMAC)
		if mac <> cipher.encrypt(msg)[:dict['taglength%i'%i]]:
			print 'ERROR for %i'%i

# CMAC-TDES2/3

from CryptoPlus.Cipher import python_DES3

for dict in dict_cmac_tdes2,dict_cmac_tdes3:
	for i in range(0,len(dict)/4):
		msg = dict['msg%i'%i].decode('hex')
		if msg == '\x00':
			msg = ''
		key = dict['key%i'%i].decode('hex')
		mac = dict['mac%i'%i].decode('hex')
		cipher = python_DES3.new(key,python_DES3.MODE_CMAC)
		if mac <> cipher.encrypt(msg)[:dict['taglength%i'%i]]:
			print 'ERROR! on %i'%i
