from pkg_resources import parse_version
import Crypto

if parse_version(Crypto.__version__) > parse_version("2.0.1"):
        del Crypto
        try:
               from Crypto.Util.python_compat import *
        except:
               from Crypto.Util.py21compat import *
