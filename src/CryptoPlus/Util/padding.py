import random

import sys
from optparse import OptionParser
from util import roundUp

class Padding():
    """Class for padding functions

    Inherits from the BlockOperator class

    padding info here: http://en.wikipedia.org/wiki/Padding_(cryptography)

    Example:
    >>> padder = Padding()
    >>> padder.pad('test','bitPadding')
    'test\\x80\\x00\\x00\\x00'
    >>> padder.unpad(_,'bitPadding')
    'test'

    PKCS7 test: trying to pad a multiple of blocksize adds a block
    >>> padder.pad('12345678','PKCS7')
    '12345678\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08'
    >>> padder.unpad(_,'PKCS7')
    '12345678'
    """

    def __init__(self,bs=8):
        self.blockSize = bs

    def pad (self, toPad, algo):
        """Pad a string

        pad (toPad, algo)
            toPad = raw string to be padded
            algo = a string to choose the padding algorithm to be used
                - "bitPadding"
                - "zerosPadding"
                - "PKCS7"
                - "ANSI_X923"
                - "ISO_10126"

            returns: a padded raw string"""
        return getattr(self,"_%(classname)s__%(algo)s" % {'classname':self.__class__.__name__,'algo':algo})(toPad)

    def unpad (self, padded, algo):
        """Unpad a string

        unpad (padded, algo)
            padded = raw string to be unpadded
            algo = a string to choose the padding algorithm that was used for padding the data
                - "bitPadding"
                - "zerosPadding"
                - "PKCS7"
                - "ANSI_X923"
                - "ISO_10126"

            returns: an unpadded raw string

        Caution: unpadding a string padded via 'zerosPadding' can give a wrong result when the original (non-padded) string
             ended in one or more zeros"""
        return getattr(self,"_%(classname)s__%(algo)s_unpad" % {'classname':self.__class__.__name__,'algo':algo})(padded)

    def __bitPadding (self, toPad ):
        padded = toPad + '\x80' + '\x00'*(self.blockSize - len(toPad)%self.blockSize -1)
        return padded

    def __bitPadding_unpad (self, padded ):
        if padded.rstrip('\x00')[-1] == '\x80':
            return padded.rstrip('\x00')[:-1]
        else:
            return padded

    def __zerosPadding (self, toPad ):
        totalLength = roundUp(len(toPad),self.blockSize)
        return toPad.ljust(totalLength,'\x00')

    def __zerosPadding_unpad (self, padded ):
        return padded.rstrip('\x00')

    def __PKCS7 (self, toPad ):
        pattern = self.blockSize - len(toPad)%self.blockSize
        code = "%02x" % pattern
        patternstring = ('\\x' + code).decode('string_escape')
        amount = self.blockSize - len(toPad)%self.blockSize
        pad = ''.join(patternstring for x in range(0,amount))
        return toPad + pad

    def __PKCS7_unpad (self, padded ):
        pattern = padded[-1]
        length = int(pattern.encode('hex'),16)
        #check if the bytes to be removed are all the same pattern
        if padded.endswith(pattern*length):
            return padded[:-length]
        else:
            return padded
            print 'error: padding pattern not recognized'

    def __ANSI_X923 (self, toPad ):
        bytesToPad = self.blockSize - len(toPad)%self.blockSize
        trail = "%02x" % bytesToPad
        pattern = '\x00'*(bytesToPad -1) + ('\\x' + trail).decode('string_escape')
        return toPad + pattern

    def __ANSI_X923_unpad (self, padded ):
        length = int(padded[-1].encode('hex'),16)
        #check if the bytes to be removed are all zero
        if padded.count('\x00',-length,-1) == length - 1:
            return padded[:-length]
        else:
            print 'error: padding pattern not recognized %s' % padded.count('\x00',-length,-1)
            return unpadded

    def __ISO_10126 (self, toPad):
        bytesToPad = self.blockSize - len(toPad)%self.blockSize
        pattern1 = ''.join(("\\x%02x" % random.randint(0,255)).decode('string_escape') for x in range(0,bytesToPad-1))
        pattern2 = ("\\x%02x" % bytesToPad).decode('string_escape')
        return toPad + pattern1 + pattern2

    def __ISO_10126_unpad (self, padded):
        return padded[0:len(padded)-int(padded[-1].encode('hex'),16)]

def main():
    usage = "usage: %prog [options] [texttopad]"
    parser = OptionParser(usage=usage)
    parser.add_option("-b", "--blocksize", dest='blocksize', default=8, help="specify the bloksize", type='int')
    (options, args) = parser.parse_args()

    if len(args) > 1:
        parser.error("Program takes maximum 1 argument")

    try:
        testbench(args[0].decode('string_escape'),options.blocksize)
    except IndexError:
        testbench(blocksize=options.blocksize)

def testbench(toPad='test',blocksize=8):
    testbench = ('bitPadding','zerosPadding','PKCS7','ANSI_X923','ISO_10126')
    padder = Padding(blocksize)
    print "String to be padded: %r, with length %i\n" % (toPad,len(toPad))
    for test in testbench:
        padded = padder.pad(toPad,'%s'%test)
        print "padded: %r" % padded
        unpadded = padder.unpad(padded,'%s'%test)
        print "unpadded: %r" % unpadded
        if unpadded == toPad:
            print "%s test OK!\n" % test
        else:
            print "%s test not OK!\n" % test

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    print 'DOCTEST'
    _test()
    print 'OTHER TESTS'
    main()
