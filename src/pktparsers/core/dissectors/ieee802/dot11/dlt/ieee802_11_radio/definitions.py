from .parse import make_config as parse_config
from .crypt import make_config as crypt_config
from .analyzers import make_config as analysis_config

BAD_FCS = "bad_fcs"
RT_HDR = "rt_hdr"

CONFIG = {
    PARSE: parse_config(),
    CRYPT: crypt_config(),
    ANALYSIS: analysis_config()
} 
