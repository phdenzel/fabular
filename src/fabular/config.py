"""
@author: phdenzel

fabular - config
"""
import os


CONF_DIR = os.path.join(os.path.expanduser("~"), '.fabular') 

# SERVER & CLIENT
LOCALHOST = '127.0.0.1'
HOST = None
PORT = '50120'
MAX_CONN = 16
ALLOW_UNKNOWN = False

# MISC
DEFAULT_ENC = 'utf-8'

# ENCRYPTION
ENCRYPTION = True
RSA_DIR = os.path.join(CONF_DIR, 'rsa')
BLOCK_SIZE = 4096

# LOGGING
VERBOSE = 3
LOG_FILE = None
MSG_PREFIX = ''
MSG_SUFFIX = '...'
