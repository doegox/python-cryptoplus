"""Self-test suite for CryptoPlus.Cipher.python_AES"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key) tuples.
# TODO: add CTR test vectors
test_data = [
('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7',
  '2b7e151628aed2a6abf7158809cf4f3c',
  'CBC 1',
  {'mode':'CBC','iv': '000102030405060708090a0b0c0d0e0f'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd',
  '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
  'CBC 2',
  {'mode':'CBC','iv': '000102030405060708090a0b0c0d0e0f'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b',
  '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  'CBC 3',
  {'mode':'CBC','iv': '000102030405060708090a0b0c0d0e0f'}),
('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6',
  '2b7e151628aed2a6abf7158809cf4f3c',
  'CFB 1',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'CFB'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  'cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff',
  '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
  'CFB 2',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'CFB'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  'dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471',
  '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  'CFB 3',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'CFB'}),
('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e',
  '2b7e151628aed2a6abf7158809cf4f3c',
  'OFB 1',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'OFB'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  'cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a',
  '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
  'OFB 2',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'OFB'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  'dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484',
  '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  'OFB 3',
  {'iv': '000102030405060708090a0b0c0d0e0f', 'mode': 'OFB'}),
('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee',
  '2b7e151628aed2a6abf7158809cf4f3c',
  'CTR 1',
  {'counter': "Crypto.Util.util.Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')",
   'mode': 'CTR'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050',
  '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
  'CTR 2',
  {'counter': "Crypto.Util.util.Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')",
   'mode': 'CTR'}),
 ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  '601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6',
  '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  'CTR 3',
  {'counter': "Crypto.Util.util.Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')",
   'mode': 'CTR'})
]

def get_tests():
    from CryptoPlus.Cipher import python_AES
    from common import make_block_tests
    return make_block_tests(python_AES, "python_AES", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

#CONVERSION OLD TEST VECTORS:
#CFB example:
#for i in range(1,len(dict_cbc_aes)/4 + 1):
#    test.append((dict_cfb_aes['msg%i'%i],dict_cfb_aes['cip%i'%i],dict_cfb_aes['key%i'%i],"CFB %i"%i,dict(mode='CFB',iv=dict_cfb_aes['iv%i'%i])))

