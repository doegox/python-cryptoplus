# =============================================================================
# Copyright (c) 2008
#     Christophe Oosterlynck (christophe.oosterlynck_AT_gmail.com)
#     Philippe Teuwen (philippe.teuwen_AT_nxp.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# =============================================================================

"""RadioGatun pure python implementation

Code based on the standard found here: http://radiogatun.noekeon.org/
Api and code interface is based on the MD5 implementation of pypy
 http://codespeak.net/pypy/dist/pypy/doc/home.html
"""

BELT_WIDTH = 3
BELT_LENGTH = 13
MILL_SIZE = 2*BELT_WIDTH + BELT_LENGTH
NUMBER_OF_BLANK_ITERATIONS = 16

def state_init():
    """construct an empty state variable
    """
    return {"A":[0]*MILL_SIZE, "B":[[0]*BELT_WIDTH for x in range(BELT_LENGTH)]}

def XOR_F_i(state, inp, wl):
    """Input mapping

    mapping input blocks to a state variable + XOR step of the alternating-
    input construction

    input = 1 blocklength string
    wl    = wordlength of the RadioGatun hash object
    """
    for i in xrange(BELT_WIDTH):
        # reverse endianness of byte ordering and convert the input
        #  block to integer
        p_i = string2number(inp[i*wl:(i+1)*wl][::-1])
        state["B"][0][i] ^= p_i
        state["A"][i+MILL_SIZE-BELT_WIDTH] ^= p_i
    return state

def R(state, wl):
    """Round function R

    state = the RadioGatun status
    wl    = wordlength of the RadioGatun hash object
    """
    out = state_init()
    # Belt function: simple rotation
    out["B"] = state["B"][-1:]+state["B"][:-1]
    # Mill to belt feedforward
    for i in xrange(BELT_LENGTH - 1):
        out["B"][i+1][i%BELT_WIDTH] ^= state["A"][i+1]
    # Run the mill
    out["A"] = Mill(state["A"], wl)
    # Belt to mill feedforward
    for i in xrange(BELT_WIDTH):
        out["A"][i+BELT_LENGTH] ^= state["B"][-1][i]
    return out

def Mill(a, wl):
    """The Mill function

    a  = Mill variable of the RadioGatun status
    wl = wordlength of the RadioGatun hash object
    """
    A = [0]*MILL_SIZE
    # Gamma: Non-linearity
    for i in xrange(MILL_SIZE):
        A[i] = a[i] ^ ~((~a[(i+1)%MILL_SIZE]) & (a[(i+2)%MILL_SIZE]) )
    # Pi: Intra-word and inter-word dispersion
    for i in xrange(MILL_SIZE):
        a[i] = rotateRight(A[(7*i)%MILL_SIZE], i*(i+1)/2, wl*8)
    # Theta: Diffusion
    for i in xrange(MILL_SIZE):
        A[i] = a[i] ^ a[(i+1)%MILL_SIZE] ^ a[(i+4)%MILL_SIZE]
    # Iota: Asymmetry
    A[0] = A[0] ^ 1
    return A

class RadioGatunType:
    "An implementation of the RadioGatun hash function in pure Python."

    def __init__(self, wl):
        """Initialisation.
        
        wl = wordlength (in bits) of the RadioGatun hash method
              between 8 and 64 (default = 64)
        """

        if not ( 8 <= wl <= 64) or not (wl%8 == 0 ):
            raise ValueError, "Wordlength should be a multiple of 8" +\
                              " between 8 and 64"

        # word & block length in bytes
        self.wordlength = wl/8
        self.blocklength = self.wordlength*BELT_WIDTH
        
        # Initial message length in bits(!).
        self.length = 0
        self.count = 0

        # Initial empty message as a sequence of bytes (8 bit characters).
        self.input = ""

        # Call a separate init function, that can be used repeatedly
        # to start from scratch on the same object.
        self.init()


    def init(self):
        """Initialize the message-digest and set all fields to zero.

        Can be used to reinitialize the hash object
        """

        self.S = state_init()

        self.length = 0
        self.count = 0
        self.input = ""

    def _transform(self, inp):
        """Basic RadioGatun step transforming the digest based on the input.

        Performs the inside of the first loop of alternating input construction
        of RadioGatun. The only thing that can be done every time new data is
        submitted to the hash object.
        Mangling and output mapping can only follow when all input data has
        been received.
        """
        T = XOR_F_i(self.S, inp, self.wordlength)
        self.S = R(T, self.wordlength)


    # Down from here all methods follow the Python Standard Library
    # API of the md5 module.

    def update(self, inBuf):
        """Add to the current message.

        Update the radiogatun object with the string arg. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments, i.e. m.update(a); m.update(b) is equivalent
        to m.update(a+b).

        The hash is immediately calculated for all full blocks. The final
        calculation is made in digest(). This allows us to keep an
        intermediate value for the hash, so that we only need to make
        minimal recalculation if we call update() to add moredata to
        the hashed string.
        """
        # Amount of bytes given at input
        leninBuf = long(len(inBuf))

        # Compute number of bytes mod 64.
        index = (self.count >> 3) % self.blocklength

        # Update number of bits.
        self.count = self.count + (leninBuf << 3)

        partLen = self.blocklength - index

        # if length of input is at least
        # the amount of bytes needed to fill a block
        if leninBuf >= partLen:
            self.input = self.input[:index] + inBuf[:partLen]
            self._transform(self.input)
            i = partLen
            while i + self.blocklength - 1 < leninBuf:
                self._transform(inBuf[i:i+self.blocklength])
                i = i + self.blocklength
            else:
                self.input = inBuf[i:leninBuf]
        # if not enough bytes at input to fill a block
        else:
            i = 0
            self.input = self.input + inBuf


    def digest(self, length=256):
        """Terminate the message-digest computation and return digest.

        length = output length of the digest in bits 
                  any multiple of 8 with a minimum of 8
                  default = 256

        Return the digest of the strings passed to the update()
        method so far. This is a byte string which may contain
        non-ASCII characters, including null bytes.
        
        Calling digest() doesn't change the internal state. Adding data via
        update() can still continu after asking for an intermediate digest
        value.
        """

        S = self.S
        inp = "" + self.input
        count = self.count

        index = (self.count >> 3) % self.blocklength

        padLen = self.blocklength - index

        padding = ['\001'] + ['\000'] * (padLen - 1)
        self.update(''.join(padding))

        # Mangling = blank rounds
        for i in xrange(NUMBER_OF_BLANK_ITERATIONS):
            self.S = R(self.S, self.wordlength)

        # Extraction
        # Store state in digest.
        digest = ""
        for i in xrange((length)/self.wordlength/2):
            self.S = R(self.S, self.wordlength)
            # F_o
            digest += \
                number2string_N((self.S["A"][1]), self.wordlength)[::-1] +\
                number2string_N((self.S["A"][2]), self.wordlength)[::-1]
 
        self.S = S
        self.input = inp
        self.count = count

        return digest[:length/8]


    def hexdigest(self, length=256):
        """Terminate and return digest in HEX form.

        length = output length of the digest in bits 
                  any multiple of 8 with a minimum of 8
                  default = 256

        Like digest() except the digest is returned as a string of
        length 'length', containing only hexadecimal digits. This may be
        used to exchange the value safely in email or other non-
        binary environments.

        Calling hexdigest() doesn't change the internal state. Adding data via
        update() can still continu after asking for an intermediate digest
        value.
        """

        return ''.join(['%02x' % ord(c) for c in self.digest(length)])

    def copy(self):
        """Return a clone object.

        Return a copy ('clone') of the radiogatun object. This can be used
        to efficiently compute the digests of strings that share
        a common initial substring.
        """

        import copy
        return copy.deepcopy(self)

# ======================================================================
# TOP LEVEL INTERFACE
# ======================================================================

def new(arg=None, wl=64):
    """Return a new RadioGatun hash object

    wl  = wordlength (in bits) of the RadioGatun hash method
              between 1 and 64 (default = 64)
    arg =  if present, the method call update(arg) is made

    EXAMPLES: (testvectors from: http://radiogatun.noekeon.org/)
    ==========
    >>> import pyradiogatun
    
    radiogatun[64]
    ---------------
    >>> hasher = pyradiogatun.new()
    >>> hasher.update('1234567890123456')
    >>> hasher.hexdigest()
    'caaec14b5b4a7960d6854709770e3071d635d60224f58aa385867e549ef4cc42'

    >>> hasher = pyradiogatun.new()
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest(480)
    '0d08daf2354fa95aaa5b6a50f514384ecdd35940252e0631002e600e13cd285f74adb0c0a666adeb1f2d20b1f2489e3d973dae4efc1f2cc5aaa13f2b'
    
    radiogatun[32]
    ---------------
    >>> hasher = pyradiogatun.new(wl=32)
    >>> hasher.update('1234567890123456')
    >>> hasher.hexdigest()
    '59612324f3f42d3096e69125d2733b86143ae668ae9ed561ad785e0eac8dba25'

    >>> hasher = pyradiogatun.new(wl=32)
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest(512)
    '041666388ef9655d48996a66dada1193d6646012a7b25a24fb10e6075cf0fc54a162949f4022531dbb6f66b64c3579df49f0f3af5951df9d68af310f2703b06d'

    radiogatun[16]
    ---------------
    >>> hasher = pyradiogatun.new(wl=16)
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest()
    'ab2203a8c3de943309b685513a29060339c001acce5900dcd6427a02c1fb8011'

    radiogatun[8]
    --------------
    >>> hasher = pyradiogatun.new(wl=8)
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest()
    'e08f5cdbbfd8f5f3c479464a60ac186963e741d28f654e2c961d2f9bebc7de31'
    """

    crypto = RadioGatunType(wl)
    if arg:
        crypto.update(arg)

    return crypto

# ======================================================================
# HELPER FUNCTIONS
# ======================================================================

def rotateRight(x, amountToShift, totalBits):
    """Rotate x (consisting of 'totalBits' bits) n bits to right.

    x             = integer input to be rotated
    amountToShift = the amount of bits that should be shifted
    totalBits     = total amount bits at the input for rotation
    """
    x = x%(2**totalBits)
    n_mod = ((amountToShift % totalBits) + totalBits) % totalBits
    return  ((x >> n_mod) | ((x << (totalBits-n_mod)))&((2**totalBits)-1))

def string2number(i):
    """ Convert a string to a number

    Input: string (big-endian)
    Output: long or integer
    """
    return int(i.encode('hex'), 16)

def number2string_N(i, N):
    """Convert a number to a string of fixed size

    i: long or integer
    N: length of string
    Output: string (big-endian)
    """
    s = '%0*x' % (N*2, i)
    return s.decode('hex')

# ======================================================================
# DOCTEST ENABLER
# ======================================================================

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    print "DOCTEST running... no messages = all good"
    _test()
