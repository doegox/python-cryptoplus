#!/usr/bin/env python

from CryptoPlus.testvectors import dict_cmac_aes128,dict_cmac_aes192,dict_cmac_aes256,dict_cmac_tdes2,dict_cmac_tdes3
from CryptoPlus.testvectors import dict_des,dict_tdes2,dict_tdes3
from CryptoPlus.testvectors import dict_serpent128,dict_serpent192,dict_serpent256
from CryptoPlus.testvectors import dict_xts_aes

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

# XTS-AES

from CryptoPlus.Cipher import python_AES

for i in range(0,len(dict_xts_aes)/5):
	msg = dict_xts_aes['msg%i'%i].decode('hex')
	key = ( dict_xts_aes['key1_%i'%i].decode('hex') , dict_xts_aes['key2_%i'%i].decode('hex') )
	cip = dict_xts_aes['cip%i'%i].decode('hex')
	n   = dict_xts_aes['n%i'%i].decode('hex')
	cipher = python_AES.new(key,python_AES.MODE_XTS)
	if cip <> cipher.encrypt(msg,n):
		print 'ERROR! for XTS on %i'%i
		print 'got %s \n expected %s'%(cipher.encrypt(msg,n).encode('hex'),cip.encode('hex'))
