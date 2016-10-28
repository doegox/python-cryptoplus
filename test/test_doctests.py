#!/usr/bin/env python

import unittest
import doctest
import re
import sys
from pkg_resources import require
require("CryptoPlus>=1.0")
#import CryptoPlus.Cipher.python_AES
from CryptoPlus.Cipher import python_AES, AES, python_DES, DES, python_DES3,\
        DES3, python_Blowfish, Blowfish, python_Twofish, python_Serpent,\
        python_Rijndael, CAST, ARC2, python_PRESENT
from CryptoPlus.Util import padding
from CryptoPlus.Hash import python_RadioGatun, python_PBKDF2, RIPEMD, python_MD5,\
     python_SHA,python_SHA256,python_SHA224,python_SHA384,python_SHA512,\
     python_whirlpool
try:
        from CryptoPlus.Cipher import IDEA
        from CryptoPlus.Cipher import RC5
        import_error = 0
except ImportError:
        import_error = 1

# from https://dirkjan.ochtman.nl/writing/2014/07/06/single-source-python-23-doctests.html
# modified for python3 to be default
class Py23DocChecker(doctest.OutputChecker):
    def check_output(self, want, got, optionflags):
        if sys.version_info[0] < 3:
            want = re.sub("b'(.*?)'", "'\\1'", want)
            want = re.sub('b"(.*?)"', '"\\1"', want)
        return doctest.OutputChecker.check_output(self, want, got, optionflags)

suite = unittest.TestSuite()
#for mod in (CryptoPlus.Cipher.python_AES,CryptoPlus.Cipher.python_AES):
for mod in python_AES, AES, python_DES, DES, python_DES3, DES3, python_Blowfish,\
           Blowfish, python_Twofish, python_Serpent, python_Rijndael, CAST, ARC2,\
           python_PRESENT, padding, python_RadioGatun, python_PBKDF2, RIPEMD,\
           python_MD5, python_SHA,python_SHA256,python_SHA224,python_SHA384,python_SHA512,\
           python_whirlpool:
    suite.addTest(doctest.DocTestSuite(mod, checker=Py23DocChecker()))
if not import_error:
    suite.addTest(doctest.DocTestSuite(IDEA, checker=Py23DocChecker()))
    suite.addTest(doctest.DocTestSuite(RC5, checker=Py23DocChecker()))
runner = unittest.TextTestRunner(verbosity=2)
runner.run(suite)

