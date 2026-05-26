from .parse import make_config as parse_config
from .crypt import make_config as crypt_config

BAD_FCS = "bad_fcs"
RT_HDR = "rt_hdr"

CONFIG = {
    PARSE: parse_config(),
    CRYPT: crypt_config() 
} 
