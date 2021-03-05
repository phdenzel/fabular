"""
fabular - tests.comm_test

@author: phdenzel
"""
import fabular.comm as fcomm
import fabular.config as fc
from tests.prototype import UnitTestPrototype
from tests.prototype import SequentialTestLoader


class CommModuleTest(UnitTestPrototype):

    def setUp(self):
        # arguments and keywords
        print("")
        print(self.separator)
        print(self.shortDescription())

    def tearDown(self):
        print("")

    def test_query_msg(self):
        """ # fabular.comm.query_msg """
        for query in ['Q:USERNAME', 'Q:CHUSERNAME', 'Q:PUBKEY', 'Q:SESSION_KEY',
                      'Q:ACCEPT', 'Q:KILL']:
            self.printf(query)
            q = fcomm.query_msg(query)
            self.assertTrue(q)
            self.assertIsInstance(q, bytes)
            self.printout(q)
        msg = 'not a query'
        self.printf(msg)
        q = fcomm.query_msg(msg)
        self.assertFalse(q)
        self.assertIsInstance(q, bytes)
        self.printout(q)

    def test_is_query(self):
        """ # fabular.comm.is_query """
        for query in ['Q:USERNAME', 'Q:CHUSERNAME', 'Q:PUBKEY',
                      'Q:SESSION_KEY', 'Q:ACCEPT', 'Q:KILL']:
            msg = fcomm.query_msg(query)
            self.printf((msg, query))
            is_q = fcomm.is_query(msg, query)
            self.assertIsInstance(is_q, bool)
            self.assertTrue(is_q)
            self.printout(is_q)
        query = 'not a query'
        msg = fcomm.query_msg(query)
        self.printf((msg, query))
        is_q = fcomm.is_query(msg, query)
        self.assertFalse(is_q)
        self.assertIsInstance(is_q, bool)
        self.printout(is_q)

    def test_verbose_level(self):
        """ # fabular.comm.verbose_level """
        for i in range(7):
            self.printf(i)
            lvl = fcomm.verbose_level(i)
            self.assertIsInstance(lvl, int)
            self.assertGreaterEqual(lvl, 0)
            if i == 0 or i == 3:
                self.assertEqual(lvl, 0)
            if i == 1:
                self.assertEqual(lvl, 10)
            if i == 2:
                self.assertEqual(lvl, 20)
            if i == 4:
                self.assertEqual(lvl, 30)
            if i == 5:
                self.assertEqual(lvl, 40)
            self.printout(lvl)

    def test_fab_msg(self):
        """ # fabular.comm.fab_msg """
        sys_keys = ['CONN', 'USRN', 'CUSR', 'DCRY', 'FDCR', 'WRYT',
                    'CHAT', 'ENTR', 'EXIT', 'INIS', 'ENDS']
        for sys_key in sys_keys:
            self.printf(sys_key)
            sys_msg = fcomm.fab_msg(sys_key)
            self.assertIsInstance(sys_msg, str)
            self.assertEqual(sys_msg, fcomm.fab_msgs[sys_key].format(
                prefix=fc.MSG_PREFIX, suffix=fc.MSG_SUFFIX).format(''))
            self.printout(sys_msg)

    def test_fab_log(self):
        """ # fabular.comm.fab_log """
        sys_keys = ['CONN', 'USRN', 'CUSR', 'DCRY', 'FDCR', 'WRYT',
                    'CHAT', 'ENTR', 'EXIT', 'INIS', 'ENDS']
        for sys_key in sys_keys:
            self.printf((sys_key, '', {'verbose_mode': 3}))
            self.assertLogs(fcomm.fab_log(sys_key, '', verbose_mode=3))


if __name__ == "__main__":

    loader = SequentialTestLoader()
    loader.proto_load(CommModuleTest)
    loader.run_suites()
