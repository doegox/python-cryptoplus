#!/usr/bin/env python

from distutils.core import setup

setup(name='CryptoPlus',
      version='1.0',
      description='PyCrypto Cipher extension',
      author='Christophe Oosterlynck',
      author_email='tiftof@gmail.com',
      url='http://www.python.org/sigs/distutils-sig/',
      packages = ["CryptoPlus","CryptoPlus.Cipher", "CryptoPlus.Util"],
      requires = ('Crypto') #http://docs.python.org/dist/node10.html
     )

