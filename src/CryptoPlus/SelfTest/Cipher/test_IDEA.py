# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/IDEA.py: Self-test for the IDEA cipher
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

"""Self-test suite for CryptoPlus.Cipher.IDEA"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from
    # http://web.archive.org/web/20001006183113/http://www.it-sec.com/pdffiles/testdata.zip

    # Test_Cases_IDEA.txt
    (b'd53fabbf94ff8b5f', b'1d0cb2af1654820a', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'848f836780938169', b'd7e0468226d0fc56', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'819440ca2065d112', b'264a8bba66959075', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'6889f5647ab23d59', b'f963468b52f45d4d', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'df8c6fc637e3dad1', b'29358cc6c83828ae', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'ac4856242b121589', b'95cd92f44bacb72d', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'cbe465f232f9d85c', b'bce24dc8d0961c44', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'6c2e3617da2bac35', b'1569e0627007b12e', b'729a27ed8f5c3e8baf16560d14c90b43'),

    # NewTestCases.txt
    (b'd53fabbf94ff8b5f', b'1320f99bfe052804', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'848f836780938169', b'4821b99f61acebb7', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'819440ca2065d112', b'c88600093b348575', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'6889f5647ab23d59', b'61d5397046f99637', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'df8c6fc637e3dad1', b'ef4899b48de5907c', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'ac4856242b121589', b'85c6b232294c2f27', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'cbe465f232f9d85c', b'b67ac767c0c06a55', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'6c2e3617da2bac35', b'b2229067630f7045', b'000027ed8f5c3e8baf16560d14c90b43'),

    (b'0000abbf94ff8b5f', b'65861be574e1eab6', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'848f836780938169', b'd7e0468226d0fc56', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'819440ca2065d112', b'264a8bba66959075', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'6889f5647ab23d59', b'f963468b52f45d4d', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'df8c6fc637e3dad1', b'29358cc6c83828ae', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'ac4856242b121589', b'95cd92f44bacb72d', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'cbe465f232f9d85c', b'bce24dc8d0961c44', b'729a27ed8f5c3e8baf16560d14c90b43'),
    (b'6c2e3617da2bac35', b'1569e0627007b12e', b'729a27ed8f5c3e8baf16560d14c90b43'),

    (b'0000abbf94ff8b5f', b'cbbb2e6c05ee8c89', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'848f836780938169', b'4821b99f61acebb7', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'819440ca2065d112', b'c88600093b348575', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'6889f5647ab23d59', b'61d5397046f99637', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'df8c6fc637e3dad1', b'ef4899b48de5907c', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'ac4856242b121589', b'85c6b232294c2f27', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'cbe465f232f9d85c', b'b67ac767c0c06a55', b'000027ed8f5c3e8baf16560d14c90b43'),
    (b'6c2e3617da2bac35', b'b2229067630f7045', b'000027ed8f5c3e8baf16560d14c90b43'),
]

def get_tests():
    from CryptoPlus.Cipher import IDEA
    from common import make_block_tests
    return make_block_tests(IDEA, "IDEA", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
