from blockcipher import *
from rijndael import rijndael

def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    Wrapper for pure python implementation rijndael.py

        key = raw string containing the key, AES-128..256 will be selected according to the key length
            -> when using XTS mode: the key should be a tuple containing the 2 keys needed
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string, default is "all zero" IV
            -> needed for CBC, CFB and OFB mode
        counter = counter object (CryptoPlus.Util.util.Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode

    Notes:
        - Always construct a seperate cipher object for encryption and decryption. Once a cipher object has been used for encryption,
          it can't be used for decryption because it keeps a state (if necessary) for the IV.

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import python_AES

    ECB EXAMPLE:
    -------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> cipher = python_AES.new('2b7e151628aed2a6abf7158809cf4f3c'.decode('hex'))
    >>> crypted = cipher.encrypt('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex'))
    >>> crypted.encode('hex')
    '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf'
    >>> decipher = python_AES.new('2b7e151628aed2a6abf7158809cf4f3c'.decode('hex'))
    >>> decipher.decrypt(crypted).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    PADDING EXAMPLE:
    -----------------
    >>> cipher = python_AES.new('0123456789012345')
    >>> crypt = cipher.encrypt('0123456789012')
    >>> crypt += cipher.final()
    >>> decipher = python_AES.new('0123456789012345')
    >>> decipher.decrypt(crypt)
    '0123456789012\\x03\\x03\\x03'

    CBC EXAMPLE (plaintext = 3 blocksizes):
    -----------------------------------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = ('2b7e151628aed2a6abf7158809cf4f3c').decode('hex')
    >>> IV = ('000102030405060708090a0b0c0d0e0f').decode('hex')
    >>> plaintext1 = ('6bc1bee22e409f96e93d7e117393172a').decode('hex')
    >>> plaintext2 = ('ae2d8a571e03ac9c9eb76fac45af8e51').decode('hex')
    >>> plaintext3 = ('30c81c46a35ce411e5fbc1191a0a52ef').decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
    >>> (ciphertext).encode('hex')
    '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
    >>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> plaintext = decipher.decrypt(ciphertext)
    >>> (plaintext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    OR: supply plaintext as seperate pieces:
    ------------------------------------------
    >>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> ( cipher.encrypt(plaintext1 + plaintext2[:-2]) ).encode('hex')
    '7649abac8119b246cee98e9b12e9197d'
    >>> ( cipher.encrypt(plaintext2[-2:] + plaintext3) ).encode('hex')
    '5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
    >>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> (decipher.decrypt(ciphertext[:22])).encode('hex')
    '6bc1bee22e409f96e93d7e117393172a'
    >>> (decipher.decrypt(ciphertext[22:])).encode('hex')
    'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    CFB EXAMPLE: (CFB8-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F
    
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=8)
    >>> ciphertext = cipher.encrypt(plain)
    >>> ciphertext.encode('hex')
    '3b79424c9c0dd436bace9e0ed4586a4f'
    >>> decipher = python_AES.new(key,python_AES.MODE_CFB,IV)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172a'

    CFB EXAMPLE: (CFB128-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> output1 = cipher.encrypt(plain)
    >>> output1.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174'
    >>> plain = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> output2 = cipher.encrypt(plain)
    >>> output2.encode('hex')
    '67ce7f7f81173621961a2b70171d3d7a'
    >>> decipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> decipher.decrypt(output1+output2).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    CFB EXAMPLE: same as previous but now as a streamcipher
    ------------
    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> output = ''
    >>> for i in plain: output += cipher.encrypt(i)
    >>> output.encode('hex')
    'cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a'

    OFB EXAMPLE: (OFB128-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> output1 = cipher.encrypt(plain)
    >>> output1.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174'
    >>> plain = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> output2 = cipher.encrypt(plain)
    >>> output2.encode('hex')
    'fcc28b8d4c63837c09e81700c1100401'
    >>> decipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> decipher.decrypt(output1 + output2).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    OFB EXAMPLE: same as previous but now as a streamcipher
    ------------
    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> output = ''
    >>> for i in plain: output += cipher.encrypt(i)
    >>> output.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c1100401'


    CTR EXAMPLE:
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> from CryptoPlus.Util.util import Counter
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> counter = Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex'))
    >>> cipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter)
    >>> plaintext1 = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> plaintext2 = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> plaintext3 = '30c81c46a35ce411e5fbc1191a0a52ef'.decode('hex')
    >>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
    >>> ciphertext.encode('hex')
    '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab'
    >>> counter2 = Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex'))
    >>> decipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter2)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    XTS EXAMPLE:
    ------------
    XTS-AES-128 applied for a data unit of 512 bytes
    IEEE P1619/D16: http://grouper.ieee.org/groups/1619/email/pdf00086.pdf

    >>> key = ('27182818284590452353602874713526'.decode('hex'),'31415926535897932384626433832795'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> ciphertext.encode('hex')
    '27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    using data sequence number n

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'22222222222222222222222222222222'.decode('hex'))
    >>> plain ='4444444444444444444444444444444444444444444444444444444444444444'.decode('hex')
    >>> n = '3333333333'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plain,n)
    >>> ciphertext.encode('hex')
    'af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '4444444444444444444444444444444444444444444444444444444444444444'

    >>> key = ('27182818284590452353602874713526'.decode('hex'),'31415926535897932384626433832795'.decode('hex'))
    >>> plain ='72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c3957a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1aecb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a09c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af79288f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43ed14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed1839e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c49d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f10699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a'.decode('hex')
    >>> n = 'ff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> cipher.encrypt(plain,n).encode('hex')
    '3260ae8dad1f4a32c5cafe3ab0eb95549d461a67ceb9e5aa2d3afb62dece0553193ba50c75be251e08d1d08f1088576c7efdfaaf3f459559571e12511753b07af073f35da06af0ce0bbf6b8f5ccc5cea500ec1b211bd51f63b606bf6528796ca12173ba39b8935ee44ccce646f90a45bf9ccc567f0ace13dc2d53ebeedc81f58b2e41179dddf0d5a5c42f5d8506c1a5d2f8f59f3ea873cbcd0eec19acbf325423bd3dcb8c2b1bf1d1eaed0eba7f0698e4314fbeb2f1566d1b9253008cbccf45a2b0d9c5c9c21474f4076e02be26050b99dee4fd68a4cf890e496e4fcae7b70f94ea5a9062da0daeba1993d2ccd1dd3c244b8428801495a58b216547e7e847c46d1d756377b6242d2e5fb83bf752b54e0df71e889f3a2bb0f4c10805bf3c590376e3c24e22ff57f7fa965577375325cea5d920db94b9c336b455f6e894c01866fe9fbb8c8d3f70a2957285f6dfb5dcd8cbf54782f8fe7766d4723819913ac773421e3a31095866bad22c86a6036b2518b2059b4229d18c8c2ccbdf906c6cc6e82464ee57bddb0bebcb1dc645325bfb3e665ef7251082c88ebb1cf203bd779fdd38675713c8daadd17e1cabee432b09787b6ddf3304e38b731b45df5df51b78fcfb3d32466028d0ba36555e7e11ab0ee0666061d1645d962444bc47a38188930a84b4d561395c73c087021927ca638b7afc8a8679ccb84c26555440ec7f10445cd'

    >>> key = ('2718281828459045235360287471352662497757247093699959574966967627'.decode('hex'),'3141592653589793238462643383279502884197169399375105820974944592'.decode('hex'))
    >>> plain ='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> n = 'ffffffffff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plain,n)
    >>> ciphertext.encode('hex')
    '64497e5a831e4a932c09be3e5393376daa599548b816031d224bbf50a818ed2350eae7e96087c8a0db51ad290bd00c1ac1620857635bf246c176ab463be30b808da548081ac847b158e1264be25bb0910bbc92647108089415d45fab1b3d2604e8a8eff1ae4020cfa39936b66827b23f371b92200be90251e6d73c5f86de5fd4a950781933d79a28272b782a2ec313efdfcc0628f43d744c2dc2ff3dcb66999b50c7ca895b0c64791eeaa5f29499fb1c026f84ce5b5c72ba1083cddb5ce45434631665c333b60b11593fb253c5179a2c8db813782a004856a1653011e93fb6d876c18366dd8683f53412c0c180f9c848592d593f8609ca736317d356e13e2bff3a9f59cd9aeb19cd482593d8c46128bb32423b37a9adfb482b99453fbe25a41bf6feb4aa0bef5ed24bf73c762978025482c13115e4015aac992e5613a3b5c2f685b84795cb6e9b2656d8c88157e52c42f978d8634c43d06fea928f2822e465aa6576e9bf419384506cc3ce3c54ac1a6f67dc66f3b30191e698380bc999b05abce19dc0c6dcc2dd001ec535ba18deb2df1a101023108318c75dc98611a09dc48a0acdec676fabdf222f07e026f059b672b56e5cbc8e1d21bbd867dd927212054681d70ea737134cdfce93b6f82ae22423274e58a0821cc5502e2d0ab4585e94de6975be5e0b4efce51cd3e70c25a1fbbbd609d273ad5b0d59631c531f6a0a57b9'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    using plaintext not a multiple of 16

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f10111213'.decode('hex')
    >>> n = '9a78563412'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '9d84c813f719aa2c7be3f66171c7c5c2edbf9dac'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f10111213'

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f10'.decode('hex')
    >>> n = '9a78563412'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '6c1625db4671522d3d7599601de7ca09ed'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f10'

    >>> key = ('e0e1e2e3e4e5e6e7e8e9eaebecedeeef'.decode('hex'),'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> n = '21436587a9'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be68b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42ccbd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad38549c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a17741990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee39936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d48b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b883342729e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    CMAC EXAMPLE:
    -------------
    NIST publication 800-38B: http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf

    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> plaintext = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')[:16]
    '070a16b46b4d4144'

    CMAC EXAMPLE2:
    --------------
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> plaintext = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')[:16]
    'dfa66747de9ae630'
    """
    return python_AES(key,mode,IV,counter,segment_size)

class python_AES(BlockCipher):
    key_error_message = ("Key should be 128, 192 or 256 bits")

    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = rijndael
        args = {'block_size':16}
        self.blocksize = 16
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

    def keylen_valid(self,key):
        return len(key) in (16,24,32)

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()
