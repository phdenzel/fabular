"""
@author: phdenzel

fabular - config
"""

# SERVER
LOCALHOST = '127.0.0.1'
HOST = None
PORT = '50120'
MAX_CONN = 16

# MISC
DEFAULT_ENC = 'utf-8'

# ENCRYPTION
ENCRYPTION = True
BLOCK_SIZE = 1024  # larger blocks = exponentially slower encryption

# LOGGING
VERBOSE = 3
LOG_FILE = None
MSG_PREFIX = ''
MSG_SUFFIX = '...'
