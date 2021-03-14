#!/usr/bin/env python
"""
@author: phdenzel

fabular - comm

Message handler, log system, etc.
"""
import logging
import fabular.config as fc
from fabular.config import MSG_PREFIX as PREFIX
from fabular.config import MSG_SUFFIX as SUFFIX

fab_msgs = {
    'CONN': '{prefix}Connected with {{}}{suffix}',
    'USRN': '{prefix}Username set to {{}}{suffix}',
    'CUSR': '{prefix}Username not allowed, choose another{suffix}',
    'DCRY': '{prefix}Setting up encryption{suffix}',
    'FDCR': '{prefix}Encryption setup failed, proceeding without{suffix}',
    'LERR': '{prefix}Login error: Username or public key mismatch{suffix}',
    'WRYT': ('{prefix}Ready to chat.\n'
             'Should you wish to leave, '
             r'type one of [\q | \quit | \exit | \leave]{suffix}'),
    'CHAT': '{prefix}{{}}{suffix}',
    'ENTR': '{prefix}{{}} entered the session{suffix}',
    'EXIT': '{prefix}{{}} has left fabular{suffix}',
    'INIS': '{prefix}Server is listening{suffix}',
    'ENDS': '{prefix}\nServer is shutting down{suffix}',
}

cmd_signals = {
    'X': [r'\{}'.format(q) for q in ['q', 'quit', 'exit', 'leave']],
}


def query_msg(query, encoding=fc.DEFAULT_ENC):
    """
    Encode query message between server and client which trigger special actions

    Args:
        query <str> - key for query message

    Kwargs:
        encoding <str> - string coding

    Return:
        q_msg <bytes> - encoded query message; if key is query else empty
    """
    q_msgs = {
        'Q:USERNAME': 'Q:USERNAME'.encode(encoding),
        'Q:CHUSERNAME': 'Q:CHUSERNAME'.encode(encoding),
        'Q:PUBKEY': 'Q:PUBKEY'.encode(encoding),
        'Q:SESSION_KEY': 'Q:SESSION_KEY'.encode(encoding),
        'Q:ACCEPT': 'Q:ACCEPT'.encode(encoding),
        'Q:KILL': 'Q:KILL'.encode(encoding),
    }
    if not query.startswith('Q:'):
        return bytes()
    if query in q_msgs:
        return q_msgs[query]
    else:
        return bytes()


def is_query(msg, query):
    """
    Check if message is a particular query

    Args:
        msg <bytes> - message to be checked
        query <str> - key query to check against

    Kwargs:
        None

    Return:
        check <bool> - True if message is an encoded query
    """
    q = query_msg(query)
    if q:
        return msg == q
    return False


def verbose_level(verbose_mode=3):
    """
    Verbose mode to logging level mapper

    Args:
        None

    Kwargs:
        verbose_mode <int> - level of verbosity [0-|1|2|3|4|5]

    Return:
        logging_lvl <int> - log levels
    """
    if verbose_mode < 1 or verbose_mode == 3:
        return logging.NOTSET
    elif verbose_mode == 2:
        return logging.INFO
    elif verbose_mode == 1:
        return logging.DEBUG
    elif verbose_mode == 4:
        return logging.WARNING
    elif verbose_mode == 5:
        return logging.ERROR
    else:
        return verbose_mode


def fab_msg(flag, *args, **kwargs):
    """
    Get system messages based on flags

    Args:
        flag <str> - determines message type ['CONN'|'EXIT']
        *args <*tuple> - arbitrary arguments according to message format

    Kwargs:
        prefix <str> - message prefix
        suffix <str> - message suffix

    Return:
        msg <str> - system message
    """
    if not args:
        args = ('',)
    msg = fab_msgs[flag].format(prefix=kwargs.pop('prefix', PREFIX),
                                suffix=kwargs.pop('suffix', SUFFIX))
    msg = msg.format(*args)
    return msg


def fab_log(message, *args, verbose_mode=3, encoding=fc.DEFAULT_ENC, **kwargs):
    """
    Log system messages in the corresponding verbose mode

    Args:
        message <str> - message to be logged
        encoding <str> - string coding

    Kwargs:
        verbose_mode <int> - level of verbosity

    Return:
        None
    """
    if message in fab_msgs:
        message = fab_msg(message, *args)
    if isinstance(message, bytes):
        message = message.decode(encoding)
    if verbose_mode == 3:
        print(message, **kwargs)
    else:
        lvl = verbose_level(verbose_mode)
        if lvl > 0:
            logging.log(lvl, message)


if fc.LOG_FILE:
    loglvl = verbose_level(fc.VERBOSE)
    logging.getLogger().setLevel(loglvl)
    logging.basicConfig(filename=fc.LOG_FILE, filemode='a',
                        level=loglvl)


if __name__ == "__main__":

    from tests.prototype import SequentialTestLoader
    from tests.comm_test import CommModuleTest
    loader = SequentialTestLoader()
    loader.proto_load(CommModuleTest)
    loader.run_suites()
