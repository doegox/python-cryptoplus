from pkg_resources import parse_version
import Crypto
__all__ = ["Cipher","PublicKey","Util","Protocol","Hash","testvectors","SelfTest"]

if parse_version(Crypto.__version__) > parse_version("2.0.1"):
        __all__.append("Random")

#del parse_version
#del Crypto
