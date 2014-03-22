PYCRYPTOPLUS
=============

TABLE OF CONTENTS
==================

1. WHAT IS CRYPTOPLUS
2. INSTALLING
3. GETTING STARTED
4. LIMITATIONS

1. WHAT IS CRYPTOPLUS
======================

PyCryptoPlus is an extension to the Python Crypto module (www.pycrypto.org).
PyCryptoPlus provides same ciphers as included in pycrypto but also new ones,
all being written 100% in Python. Some additional chaining modes have been
added, also in pure Python, while the ones already available in pycrypto are
provided in pure python in this package.
The reasoning is that Python code has the advantage to be more readable and
so easier to be adapted to your needs or experiments.
All other functions of pycrypto are still available via the interface
of CryptoPlus. The new cipher implementations can be accessed via
CryptoPlus.Cipher.python_* while the original ones from pycrypto are
still available under their original name via CryptoPlus.Cipher.*.
When using the original ciphers, the original pycrypto code written in C is
used but the chaining modes being used are the new ones in Python.

New functions:
    Ciphers:
        Rijndael
        Serpent
        Twofish
    Chaining Modes:
        XTS
        CMAC

Note: for the cipher algorithms, code has been reused from third parties.
Corresponding copyright notices are available in their source code.

2. INSTALLING
==============

required packages before installing:
    - python-setuptools
    - python-pkg-resources

python setup.py install

3. GETTING STARTED
===================

Same API from PyCrypto can be used. See:
http://www.dlitz.net/software/pycrypto/doc/

Biggest changes are the addition of some chain modes and block ciphers.
A lot of examples are provided as docstrings.
Have a look at them in '../CryptoPlus/Cipher/*.py' or via an interactive
python session by using 'CryptoPlus.Cipher.python_AES.new?'.
Once a cipher object is constructed with
'cipher = CryptoPlus.Cipher.python_AES.new(...)'
you can get more info about encrypting and decrypting by reading
the apprioprate docstring ('cipher.encrypt?','cipher.decrypt?').

Some test functions are provided in the docstrings and in the 'test'
folder. Run all the doctests in the new Cipher function by using
the '../test/test_doctest.py' script. '../test/test.py' provides
some test function for the testvectors available from the module via
'CryptoPlus.Cipher.testvectors'. Have a look at the test.py sourcecode
to have an idea of how to use those test vectors.

4. LIMITATIONS
===============

CMAC can only be used with ciphers of 64 or 128 bits blocksizes
XTS can only be used with ciphers of 128 bits blocksize
