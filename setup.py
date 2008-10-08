#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='CryptoPlus',
      version='1.0',
      description='PyCrypto Cipher extension',
      author='Christophe Oosterlynck',
      author_email='tiftof@gmail.com',
      packages = find_packages('src'),
      install_requires = ['pycrypto'],
      package_dir={'': 'src'}
     )

