#!/usr/bin/env python
"""
fabular - test

@author: phdenzel
"""
from tests.prototype import SequentialTestLoader
from tests.server_test import ServerModuleTest
from tests.client_test import ClientModuleTest
from tests.comm_test import CommModuleTest
from tests.crypt_test import CryptModuleTest
from tests.utils_test import UtilsModuleTest


def main():

    loader = SequentialTestLoader()

    loader.proto_load(ServerModuleTest)
    loader.proto_load(ClientModuleTest)
    loader.proto_load(CommModuleTest)
    loader.proto_load(CryptModuleTest)
    loader.proto_load(UtilsModuleTest)

    loader.run_suites(verbosity=1)


if __name__ == "__main__":

    # main()

    import sys
    import fabular.config as fc
    from pyngrok import ngrok
    
    tcp_tunnel = ngrok.connect(fc.PORT, "tcp")
    print(tcp_tunnel.__dict__)

    
