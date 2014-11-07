# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/ARC2.py: Self-test for the Alleged-RC2 cipher
#
# =======================================================================
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================
#

"""Self-test suite for CryptoPlus.Cipher.ARC2"""

__revision__ = "$Id$"

from common import dict     # For compatibility with Python 2.1 and 2.2

# This is a list of (plaintext, ciphertext, key[, description[, extra_params]]) tuples.
test_data = [
    # Test vectors from RFC 2268

    # 63-bit effective key length
    (b'0000000000000000', b'ebb773f993278eff', b'0000000000000000',
        'RFC2268-1', dict(effective_keylen=63)),

    # 64-bit effective key length
    (b'ffffffffffffffff', b'278b27e42e2f0d49', b'ffffffffffffffff',
        'RFC2268-2', dict(effective_keylen=64)),
    (b'1000000000000001', b'30649edf9be7d2c2', b'3000000000000000',
        'RFC2268-3', dict(effective_keylen=64)),
    (b'0000000000000000', b'61a8a244adacccf0', b'88',
        'RFC2268-4', dict(effective_keylen=64)),
    (b'0000000000000000', b'6ccf4308974c267f', b'88bca90e90875a',
        'RFC2268-5', dict(effective_keylen=64)),
    (b'0000000000000000', b'1a807d272bbe5db1', b'88bca90e90875a7f0f79c384627bafb2',
        'RFC2268-6', dict(effective_keylen=64)),

    # 128-bit effective key length
    (b'0000000000000000', b'2269552ab0f85ca6', b'88bca90e90875a7f0f79c384627bafb2',
        "RFC2268-7", dict(effective_keylen=128)),
    (b'0000000000000000', b'5b78d3a43dfff1f1',
        b'88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e',
        "RFC2268-8", dict(effective_keylen=129)),

    # Test vectors from PyCryptoPlus 2.0.1's testdata.py
    # 1024-bit effective key length
    (b'0000000000000000', b'624fb3e887419e48', b'5068696c6970476c617373',
        'PCTv201-0',dict(effective_keylen=1024)),
    (b'ffffffffffffffff', b'79cadef44c4a5a85', b'5068696c6970476c617373',
        'PCTv201-1',dict(effective_keylen=1024)),
    (b'0001020304050607', b'90411525b34e4c2c', b'5068696c6970476c617373',
        'PCTv201-2',dict(effective_keylen=1024)),
    (b'0011223344556677', b'078656aaba61cbfb', b'5068696c6970476c617373',
        'PCTv201-3',dict(effective_keylen=1024)),
    (b'0000000000000000', b'd7bcc5dbb4d6e56a', b'ffffffffffffffff', 'PCTv201-4',dict(effective_keylen=1024)),
    (b'ffffffffffffffff', b'7259018ec557b357', b'ffffffffffffffff', 'PCTv201-5',dict(effective_keylen=1024)),
    (b'0001020304050607', b'93d20a497f2ccb62', b'ffffffffffffffff', 'PCTv201-6',dict(effective_keylen=1024)),
    (b'0011223344556677', b'cb15a7f819c0014d', b'ffffffffffffffff', 'PCTv201-7',dict(effective_keylen=1024)),
    (b'0000000000000000', b'63ac98cdf3843a7a',
        b'ffffffffffffffff5065746572477265656e6177617953e5ffe553',
        'PCTv201-8',dict(effective_keylen=1024)),
    (b'ffffffffffffffff', b'3fb49e2fa12371dd',
        b'ffffffffffffffff5065746572477265656e6177617953e5ffe553',
        'PCTv201-9',dict(effective_keylen=1024)),
    (b'0001020304050607', b'46414781ab387d5f',
        b'ffffffffffffffff5065746572477265656e6177617953e5ffe553',
        'PCTv201-10',dict(effective_keylen=1024)),
    (b'0011223344556677', b'be09dc81feaca271',
        b'ffffffffffffffff5065746572477265656e6177617953e5ffe553',
        'PCTv201-11',dict(effective_keylen=1024)),
    (b'0000000000000000', b'e64221e608be30ab', b'53e5ffe553', 'PCTv201-12',dict(effective_keylen=1024)),
    (b'ffffffffffffffff', b'862bc60fdcd4d9a9', b'53e5ffe553', 'PCTv201-13',dict(effective_keylen=1024)),
    (b'0001020304050607', b'6a34da50fa5e47de', b'53e5ffe553', 'PCTv201-14',dict(effective_keylen=1024)),
    (b'0011223344556677', b'584644c34503122c', b'53e5ffe553', 'PCTv201-15',dict(effective_keylen=1024)),
]

def get_tests():
    from CryptoPlus.Cipher import ARC2
    from common import make_block_tests
    return make_block_tests(ARC2, "ARC2", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
