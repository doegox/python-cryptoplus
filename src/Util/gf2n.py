## gf2n.py - Arithmetic in GF(2^n).
## Copyright (c) 2008 Bjorn Edstrom <be@bjrn.se>
##
## Permission is hereby granted, free of charge, to any person
## obtaining a copy of this software and associated documentation
## files (the "Software"), to deal in the Software without
## restriction, including without limitation the rights to use,
## copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the
## Software is furnished to do so, subject to the following
## conditions:
##
## The above copyright notice and this permission notice shall be
## included in all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
## OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
## NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
## HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
## WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
## FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
## OTHER DEALINGS IN THE SOFTWARE.
## --
## Changelog
## Jan 4 2008: Initial version.

try:
    import psyco
    psyco.full()
except ImportError:
    pass

mod128 = 0x100000000000000000000000000000087L # x^128+x^7+x^2+x+1

# A detailed explanation of how this works can be found at
# http://en.wikipedia.org/wiki/Finite_field_arithmetic
# In short what we are doing is multiplying polynomials where each term is
# modulo 2. For this reason we can represent the polynomials as a binary
# string. For example, the polynomial x^3 + x + 1 = x^3 + x^1 + x^0 is the
# binary string 1011b. Here's a short example. Let us multiply
# (x + 1) with (x^3 + x^2): (x + 1)(x^3 + x^2) = x(x^3 + x^2) + x^3 + x^2 =
# x^4 + x^3 + x^3 + x^2 = x^4 + 2x^3 + x^2
# This is regular multiplication. However, as each term is modulo 2
# we're left with (1 % 2)x^4 + (2 % 2)x^3 + (1 % 2)x^2 = x^4 + x^2.
# There is however one step remaining: Depending of the field we're multiplying
# in there's modulo step left. For GF(2^8) the modulo is 100011011b
# and for GF(2^128) the modulo is x^128+x^7+x^2+x+1.
# This modulo step can be performed with simple long division but by
# binary OR:ing instead of subtracting.

def gf2n_mul(a, b, mod):
    """Multiplication in GF(2^n)."""

    def highest_bit_set(n):
        # XXX: naive
        cnt = 0
        while n:
            n >>= 1
            cnt += 1
        return cnt - 1  

    def xor_mod(n, mod):
        while True:
            x = highest_bit_set(n) - highest_bit_set(mod)
     
            if x == 0:
                n = n ^ mod
            if x <= 0:
                break
            lower = n & ((1 << x) - 1)
            n = (((n >> x) ^ mod) << x) | lower
        return n        

    # Naively mutiply two polynomials together. Lets say a is x^8+x^3+1
    # and b is x^4+x^2, then we can write this as the following pseudo code:
    res = 0
    a_cnt = 0
    # for each term in [x^8, x^3, 1]:
    while a:
        b2 = b
        b_cnt = 0
        if a & 1:
            # for each term in [x^4, x^2]:
            while b2:
                if b2 & 1:
                    # 1 << (a_cnt + b_cnt) constructs the new term
                    # and the xor adds it to the result modulo 2.
                    res ^= 1 << (a_cnt + b_cnt)
                b2 >>= 1
                b_cnt += 1
        a >>= 1
        a_cnt += 1
        
    return xor_mod(res, mod)

def gf2pow128mul(a, b):
    return gf2n_mul(a, b, mod128)

# Add and subtract polynomials modulo 2. See explanation above why this
# code is so simple.

def gf2n_add(a, b):
    """Addition in GF(2^n)."""
    return a ^ b

def gf2n_sub(a, b):
    """Subtraction in GF(2^n)."""
    return a ^ b

#
# Tests.
#

assert gf2n_mul(0x53, 0xca, 0x11b) == 1
assert gf2pow128mul(0xb9623d587488039f1486b2d8d9283453, 0xa06aea0265e84b8a) == 0xfead2ebe0998a3da7968b8c2f6dfcbd2
assert gf2pow128mul(0x0696ce9a49b10a7c21f61cea2d114a22, 0x8258e63daab974bc) == 0x89a493638cea727c0bb06f5e9a0248c7
assert gf2pow128mul(0xecf10f64ceff084cd9d9d1349c5d1918, 0xf48a39058af0cf2c) == 0x80490c2d2560fe266a5631670c6729c1
assert gf2pow128mul(0x9c65a83501fae4d5672e54a3e0612727, 0x9d8bc634f82dfc78) == 0xd0c221b4819fdd94e7ac8b0edc0ab2cb
assert gf2pow128mul(0xb8885a52910edae3eb16c268e5d3cbc7, 0x98878367a0f4f045) == 0xa6f1a7280f1a89436f80fdd5257ec579
assert gf2pow128mul(0xd91376456609fac6f85748784c51b272, 0xf6d1fa7f5e2c73b9) == 0xbcbb318828da56ce0008616226d25e28
assert gf2pow128mul(0x0865625a18a1aace15dba90dedd95d27, 0x395fcb20c3a2a1ff) == 0xa1c704fc6e913666c7bd92e3bc2cbca9
assert gf2pow128mul(0x45ff1a2274ed22d43d31bb224f519fea, 0xd94a263495856bc5) == 0xd0f6ce03966ba1e1face79dfce89e830
assert gf2pow128mul(0x0508aaf2fdeaedb36109e8f830ff2140, 0xc15154674dea15bf) == 0x67e0dbe4ddff54458fa67af764d467dd
assert gf2pow128mul(0xaec8b76366f66dc8e3baaf95020fdfb5, 0xd1552daa9948b824) == 0x0a3c509baed65ac69ec36ae7ad03cc24
assert gf2pow128mul(0x1c2ff5d21b5555781bbd22426912aa58, 0x5cdda0b2dafbbf2e) == 0xc9f85163d006bebfc548d010b6590cf2
assert gf2pow128mul(0x1d4db0dfb7b12ea8d431680ac07ba73b, 0xa9913078a5c26c9b) == 0x6e71eaf1e7276f893a9e98a377182211
assert gf2pow128mul(0xf7d946f08e94d545ce583b409322cdf6, 0x73c174b844435230) == 0xad9748630fd502fe9e46f36328d19e8d
assert gf2pow128mul(0xdeada9ae22eff9bc3c1669f824c46823, 0x6bdd94753484db33) == 0xc40822f2f3984ed58b24bd207b515733
assert gf2pow128mul(0x8146e084b094a0814577558be97f9be1, 0xb3fdd171a771c2ef) == 0xf0093a3df939fe1922c6a848abfdf474
assert gf2pow128mul(0x7c468425a3bda18a842875150b58d753, 0x6358fcb8015c9733) == 0x369c44a03648219e2b91f50949efc6b4
assert gf2pow128mul(0xe5f445041c8529d28afad3f8e6b76721, 0x06cefb145d7640d1) == 0x8c96b0834c896435fe8d4a70c17a8aff

