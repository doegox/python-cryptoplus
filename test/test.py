#!/usr/bin/env python

from pkg_resources import require
require("CryptoPlus>=1.0")
from CryptoPlus.testvectors import dict_ofb_aes, dict_ctr_aes, dict_cfb_aes, dict_cbc_aes
from CryptoPlus.testvectors import dict_cmac_aes128,dict_cmac_aes192,dict_cmac_aes256,dict_cmac_tdes2,dict_cmac_tdes3
from CryptoPlus.testvectors import dict_des,dict_tdes2,dict_tdes3
from CryptoPlus.testvectors import dict_serpent128,dict_serpent192,dict_serpent256
from CryptoPlus.testvectors import dict_xts_aes

# PRESENT
print "PRESENT"

from CryptoPlus.testvectors import dict_present_e80_k12_tvar, dict_present_e128_k12_tvar, dict_present_e128_kvar_t12, dict_present_e80_kvar_t12
from CryptoPlus.Cipher import python_PRESENT

for i in range(1,len(dict_present_e80_k12_tvar)/3):
    msg = dict_present_e80_k12_tvar['msg%i'%i].decode('hex')
    key = dict_present_e80_k12_tvar['key%i'%i].decode('hex')
    cip = dict_present_e80_k12_tvar['cip%i'%i].decode('hex')
    cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    decipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for present_e80-k12_tvar in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for present_e80-k12_tvar in %i'%i

for i in range(1,len(dict_present_e128_k12_tvar)/3):
    msg = dict_present_e128_k12_tvar['msg%i'%i].decode('hex')
    key = dict_present_e128_k12_tvar['key%i'%i].decode('hex')
    cip = dict_present_e128_k12_tvar['cip%i'%i].decode('hex')
    cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    decipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for present_e128-k12_tvar in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for present_e128-k12_tvar in %i'%i

for i in range(1,len(dict_present_e128_kvar_t12)/3):
    msg = dict_present_e128_kvar_t12['msg%i'%i].decode('hex')
    key = dict_present_e128_kvar_t12['key%i'%i].decode('hex')
    cip = dict_present_e128_kvar_t12['cip%i'%i].decode('hex')
    cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    decipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for present_e128-kvar_t12 in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for present_e128-kvar_t12 in %i'%i

for i in range(1,len(dict_present_e80_kvar_t12)/3):
    msg = dict_present_e80_kvar_t12['msg%i'%i].decode('hex')
    key = dict_present_e80_kvar_t12['key%i'%i].decode('hex')
    cip = dict_present_e80_kvar_t12['cip%i'%i].decode('hex')
    cipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    decipher = python_PRESENT.new(key,python_PRESENT.MODE_ECB)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for present_e80-kvar_t12 in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for present_e80-kvar_t12 in %i'%i

# CBC, CFB, OFB and CTR with AES
print "AES"

from CryptoPlus.Cipher import python_AES
from CryptoPlus.Util import util

for i in range(1,len(dict_cbc_aes)/4+1):
    msg = dict_cbc_aes['msg%i'%i].decode('hex')
    iv = dict_cbc_aes['iv%i'%i].decode('hex')
    key = dict_cbc_aes['key%i'%i].decode('hex')
    cip = dict_cbc_aes['cip%i'%i].decode('hex')
    cipher = python_AES.new(key,python_AES.MODE_CBC,iv)
    decipher = python_AES.new(key,python_AES.MODE_CBC,iv)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for CBC-AES in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for CBC-AES in %i'%i

for i in range(1,len(dict_ctr_aes)/4+1):
    msg = dict_ctr_aes['msg%i'%i].decode('hex')
    ctr = dict_ctr_aes['ctr%i'%i].decode('hex')
    key = dict_ctr_aes['key%i'%i].decode('hex')
    cip = dict_ctr_aes['cip%i'%i].decode('hex')
    counter = util.Counter(ctr)
    counter2= util.Counter(ctr)
    cipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter)
    decipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter2)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for CTR-AES in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for CTR-AES in %i'%i

for i in range(1,len(dict_ofb_aes)/4+1):
    msg = dict_ofb_aes['msg%i'%i].decode('hex')
    iv = dict_ofb_aes['iv%i'%i].decode('hex')
    key = dict_ofb_aes['key%i'%i].decode('hex')
    cip = dict_ofb_aes['cip%i'%i].decode('hex')
    cipher = python_AES.new(key,python_AES.MODE_OFB,IV=iv)
    decipher = python_AES.new(key,python_AES.MODE_OFB,IV=iv)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for OFB-AES in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for OFB-AES in %i'%i

for i in range(1,len(dict_cfb_aes)/4+1):
    msg = dict_cfb_aes['msg%i'%i].decode('hex')
    iv = dict_cfb_aes['iv%i'%i].decode('hex')
    key = dict_cfb_aes['key%i'%i].decode('hex')
    cip = dict_cfb_aes['cip%i'%i].decode('hex')
    cipher = python_AES.new(key,python_AES.MODE_CFB,IV=iv)
    decipher = python_AES.new(key,python_AES.MODE_CFB,IV=iv)
    if cip <> cipher.encrypt(msg):
        print 'ERROR! for CFB-AES in %i'%i
    if msg <> decipher.decrypt(cip):
        print 'DECRYPTION ERROR! for CFB-AES in %i'%i

# DES,TDES2/3
print "DES TDES2/3"

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
print "Serpent"

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
print "CMAC-AES"

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
print "CMAC-TDES"
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
print "XTS-AES"

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
