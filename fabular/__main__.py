"""
fabular - main

Launch a fabular instance which runs a server or connects to an address

@author: phdenzel
"""
import fabular.config as fc


def parse_cfg(filename):
    from configparser import ConfigParser
    cfg = ConfigParser()
    cfg.read(filename)
    return cfg


def arg_parse():
    from argparse import ArgumentParser, RawTextHelpFormatter
    p = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)

    p.add_argument("--host", dest="host", metavar="<host>", type=str,
                   help="TCP host IP address")
    p.add_argument("-p", "--port", dest="port", metavar="<port>", type=str,
                   help="TCP endpoint, i.e. port number of the host IP address")
    p.add_argument("--max-conn", dest="max_conn", metavar="<max_conn>", type=str,
                   help="Connection limit of the TCP server")
    p.add_argument("--encoding", dest="default_enc", metavar="<encoding>", type=str,
                   help="Default byte-encoding of the messages")
    p.add_argument("--no-encryption", dest="encryption", action="store_false",
                   help=("No-Encryption flag [default: false];\nset to true "
                         "if communication is supposed to be unencrypted"), default=True)
    p.add_argument("-b", "--block-size", dest="block_size", metavar="<block_size>", type=int,
                   help="Block size of the TCP data stream")
    p.add_argument("-l", "--log-file", dest="log_file", metavar="<filename>", type=str,
                   help="Pathname of the optional log-file")
    p.add_argument("-v", "--verbose", dest="verbose", metavar="<level>", type=int,
                   help="Define level of verbosity")

    p.add_argument("-s", "--server", "--server-mode", "--start-server", "--run-server",
                   dest="as_client", action="store_false", default=True)
    p.add_argument("-c", "--client", "--client-mode", "--start-client", "--run-client",
                   dest="as_client", action="store_true", default=True)
    p.add_argument("-t", "--test", "--test-mode", dest="test_mode", action="store_true",
                   help="Run program in testing mode", default=False)

    args = p.parse_args()
    return p, args


def config_override(args, cfgs):
    # TODO: use cfgs to override args
    for key in fc.__dict__:
        if key.startswith('__'):
            continue
        if key.lower() in args and args.__getattribute__(key.lower()) is not None:
            fc.__dict__[key] = args.__getattribute__(key.lower())
            # print("Override ", key, args.__getattribute__(key.lower()))


if __name__ == "__main__":

    parser, args = arg_parse()

    # cfg = parse_cfg(['server.cfg', 'client.cfg'])
    # for key in cfg['server']:
    #     print(key, "=", cfg['server'].get(key))
    # for key in cfg['client']:
    #     print(key, "=", cfg['client'].get(key))

    if args.test_mode:  # run test suite
        config_override(args, {})
        from test import main
        main()
    elif args.as_client:  # run client instance
        config_override(args, {})
        from fabular.client import main
        main()
    else:  # run server instance
        config_override(args, {})
        from fabular.server import main
        main()
