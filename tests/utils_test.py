"""
fabular - tests._test

@author: phdenzel
"""
import os
import fabular.utils as futils
import fabular.config as fc
from tests.prototype import UnitTestPrototype
from tests.prototype import SequentialTestLoader


class UtilsModuleTest(UnitTestPrototype):

    def setUp(self):
        # arguments and keywords
        print("")
        print(self.separator)
        print(self.shortDescription())

    def tearDown(self):
        print("")

    def test_xterm256_color(self):
        """ # fabular.utils.xterm256_color """
        for i in [1, 255, 256]:
            self.printf(i)
            clr = futils.xterm256_color(i)
            self.assertIsInstance(clr, str)
            self.assertTrue(clr.endswith('{:03d}m'.format(i % 256)))
            self.printout(clr)

    def test_id_color(self):
        """ # fabular.utils.id_color """
        # futils.id_color
        for args in ['red', 'green', 'blue', 'turquoise', 'viridian',
                     'mock_client', 'fenix']:
            self.printf(args)
            clr = futils.id_color(args)
            clr_str = futils.ansi_map[clr]+"{}".format(args)+futils.ansi_map['reset']
            print(clr_str)

    def test_assign_color(self):
        """ # fabular.utils.assign_color """
        clr_lyst = []
        for args in ['red', 'green', 'blue', 'turquoise', 'viridian',
                     'mock_client', 'fenix']:
            self.printf((args, clr_lyst))
            clr = futils.assign_color(args, clr_lyst)
            clr_lyst.append(clr)
            clr_str = futils.ansi_map[clr]+"{}".format(args)+futils.ansi_map['reset']
            print(clr_str)

    def test_mkdir_p(self):
        """ # fabular.utils.mkdir_p """
        filename = 'tmp'
        exists = os.path.exists(filename)
        self.assertFalse(exists)
        self.printf(filename)
        futils.mkdir_p(filename)
        exists = os.path.exists(filename)
        self.assertTrue(exists)
        os.rmdir(filename)


if __name__ == "__main__":
    loader = SequentialTestLoader()
    loader.proto_load(UtilsModuleTest)
    loader.run_suites()
