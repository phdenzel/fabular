#!/usr/bin/env python
"""
fabular - test

@author: phdenzel
"""
from tests.prototype import SequentialTestLoader
from tests.server_test import ServerModuleTest


def main():
    loader = SequentialTestLoader()
    loader.proto_load(ServerModuleTest)

    loader.run_suites(verbosity=1)


if __name__ == "__main__":
    main()
