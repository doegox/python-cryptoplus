from pyradiogatun import RadioGatunType

__all__ = ['new']

def new(data=None,wl=64):
    """Create a new pure python RadioGatun hash object

    wl   = wordlength (in bits) of the RadioGatun hash method
              between 1 and 64 (default = 64)
    data =  if present, the method call update(arg) is made

    EXAMPLES: (testvectors from: http://radiogatun.noekeon.org/)
    ==========
    >>> import python_RadioGatun
    
    radiogatun[64]
    ---------------
    >>> hasher = python_RadioGatun.new()
    >>> hasher.update('1234567890123456')
    >>> hasher.hexdigest()
    'caaec14b5b4a7960d6854709770e3071d635d60224f58aa385867e549ef4cc42'

    >>> hasher = python_RadioGatun.new()
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest()
    '0d08daf2354fa95aaa5b6a50f514384ecdd35940252e0631002e600e13cd285f'
    
    radiogatun[32]
    ---------------
    >>> hasher = python_RadioGatun.new(wl=32)
    >>> hasher.update('1234567890123456')
    >>> hasher.hexdigest()
    '59612324f3f42d3096e69125d2733b86143ae668ae9ed561ad785e0eac8dba25'

    >>> hasher = python_RadioGatun.new(wl=32)
    >>> hasher.update('Santa Barbara, California')
    >>> hasher.hexdigest()
    '041666388ef9655d48996a66dada1193d6646012a7b25a24fb10e6075cf0fc54'
    """

    crypto = RadioGatunType(wl)
    if data:
        crypto.update(data)

    return crypto

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    print "DOCTEST running... no messages = all good"
    _test()
