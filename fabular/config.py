"""
fabular - config

@author: phdenzel
"""

# SERVER
LOCALHOST = '127.0.0.1'
HOST = None
PORT = '64242'

# MISC
DEFAULT_ENC = 'ascii'

# ENCRYPTION
RSA_bits = 4096  # 2048

# LOGGING
VERBOSE = 3
LOG_FILE = None
MSG_PREFIX = ''
MSG_SUFFIX = '...'
SYS_MSGS = {
    'CONN': '{prefix}Connected with {{}}{suffix}',
    'USRN': '{prefix}Username set to {{}}{suffix}',
    'CUSR': '{prefix}Username already taken, choose another{suffix}',
    'ENTR': '{prefix}{{}} entered the session{suffix}',
    'EXIT': '{prefix}{{}} has left fabular{suffix}',
    'CHAT': '{prefix}{{}}{suffix}',
    'INIS': '{prefix}Server is listening{suffix}',
    'ENDS': '{prefix}\nServer is shutting down{suffix}',
}
