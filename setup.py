#!/usr/bin/env python

from setuptools import setup

setup(name='CryptoPlus',
      version='1.0',
      description='PyCrypto Cipher extension',
      author='Christophe Oosterlynck',
      author_email='tiftof@gmail.com',
      url='http://www.python.org/sigs/distutils-sig/',
      packages = ["CryptoPlus","CryptoPlus.Cipher", "CryptoPlus.Util","CryptoPlus.SelfTest","CryptoPlus.Random","CryptoPlus.SelfTest.Hash"],
      install_requires = ['pycrypto'],
      package_dir = {'CryptoPlus': 'src'}
     )

