#!/usr/bin/env python

import unittest
import doctest
#import CryptoPlus.Cipher.python_AES 
from CryptoPlus.Cipher import python_AES, AES, python_DES, DES, python_DES3, DES3, python_Blowfish, Blowfish, python_Twofish, python_Serpent, python_Rijndael

suite = unittest.TestSuite()
#for mod in (CryptoPlus.Cipher.python_AES,CryptoPlus.Cipher.python_AES):
for mod in python_AES, AES, python_DES, DES, python_DES3, DES3, python_Blowfish, Blowfish, python_Twofish, python_Serpent, python_Rijndael:
    suite.addTest(doctest.DocTestSuite(mod))
runner = unittest.TextTestRunner()
runner.run(suite)

