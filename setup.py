#!/usr/bin/env python

from setuptools import setup

setup(name='CryptoPlus',
      version='1.0',
      description='PyCrypto Cipher extension',
      author='Christophe Oosterlynck',
      author_email='tiftof@gmail.com',
      packages = ["CryptoPlus","CryptoPlus.Cipher", "CryptoPlus.Util","CryptoPlus.SelfTest"],
      install_requires = ['pycrypto'],
      package_dir = {'CryptoPlus': 'src'}
     )

