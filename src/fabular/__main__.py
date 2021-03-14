"""
@author: phdenzel

fabular - main

Launch a fabular instance which runs a server or connects to an address
"""
import fabular.config as fc

__all__ = ['main']


def parse_cfg(filename):
    from configparser import ConfigParser
    cfg = ConfigParser()
    cfg.read(filename)
    return cfg


def arg_parse():
    from argparse import ArgumentParser, RawTextHelpFormatter
    p = ArgumentParser(prog='fabular', #description=__doc__,
                       formatter_class=RawTextHelpFormatter)

    # General flags
    p.add_argument("-c", "--client", "--client-mode", "--start-client", "--run-client",
                   dest="as_client", action="store_true", default=True,
                   help="Run fabular in client mode and connect to a server")
    p.add_argument("-s", "--server", "--server-mode", "--start-server", "--run-server",
                   dest="as_client", action="store_false", default=True,
                   help="Run fabular in server mode and listen for new connections")
    p.add_argument("-p", "--port", dest="port", metavar="<port>", type=str,
                   help="TCP endpoint, i.e. port number of the host IP address")
    p.add_argument("-l", "--log-file", dest="log_file", metavar="<filename>", type=str,
                   help="Pathname of the optional log-file")
    p.add_argument("-v", "--verbose", dest="verbose", metavar="<level>", type=int,
                   help="Define level of verbosity")
    p.add_argument("-t", "--test", "--test-mode", dest="test_mode", action="store_true",
                   help="Run program in testing mode", default=False)

    # Client flags
    pc = p.add_argument_group("Client specific")
    pc.add_argument("--host", dest="host", metavar="<host>", type=str,
                    help="TCP host IP address")
    pc.add_argument("--no-encryption", dest="encryption", action="store_false",
                    help=("No-Encryption flag [default: false];\nuse "
                          "if communication is supposed to be unencrypted"), default=True)

    # Server flags
    ps = p.add_argument_group("Server specific")
    ps.add_argument("--localhost", dest="localhost", metavar="<localhost>", type=str,
                    help="Local TCP host address")
    ps.add_argument("--max-conn", dest="max_conn", metavar="<max_conn>", type=int,
                    help="Connection limit of the TCP server")
    ps.add_argument("--allow-unknown", dest="allow_unknown", action="store_true",
                    help=(f"Allow unknown users to connect. "
                         "New connections will be added "
                          "to {}/known_users".format(fc.RSA_DIR)))

    # p.add_argument("--encoding", dest="default_enc", metavar="<encoding>", type=str,
    #                help="Default byte-encoding of the messages")
    # p.add_argument("-b", "--block-size", dest="block_size", metavar="<block_size>", type=int,
    #                help="Block size of the TCP data stream")


    args = p.parse_args()
    return p, args


def config_override(args, configs={}):
    # TODO: use cfgs to override args
    for key in fc.__dict__:
        if key.startswith('__'):
            continue
        if key.lower() in args and args.__getattribute__(key.lower()) is not None:
            fc.__dict__[key] = args.__getattribute__(key.lower())
    return args


def main():
    parser, args = arg_parse()

    if args.test_mode:  # run test suite
        args = config_override(args)
        from test import main
    elif args.as_client:  # run client instance
        args = config_override(args)
        from fabular.client import main
    else:  # run server instance
        args = config_override(args)
        from fabular.server import main
    main()
