"""
fabular - tests.client_test

@author: phdenzel
"""
import time
import socket
import threading
import fabular.client as fclt
from fabular.server import init_server
from fabular.crypt import Secrets
from tests.prototype import UnitTestPrototype
from tests.prototype import SequentialTestLoader


class ClientModuleTest(UnitTestPrototype):

    def setUp(self):
        # arguments and keywords
        self.addr = ('127.0.0.1', 65332)
        self.msg = ("I've wrestled with an alligator, "
                    "I done tussle with a whale, "
                    "I done handcuffed lightnin'"
                    "and thrown thunder in jail."
                    "Only last week I murdered a rock, "
                    "injured a stone, hospitalized a brick. "
                    "I'm so mean, I make medicine sick.")
        self.server = init_server(*self.addr)
        print("")
        print(self.separator)
        print(self.shortDescription())

    def tearDown(self):
        try:
            self.server.close()
        except AttributeError:
            pass
        self.server = None
        time.sleep(0.01)
        print("")

    def test_connect_server(self):
        """ # fabular.client.connect_server """
        self.printf(self.addr)
        cclient = fclt.connect_server(*self.addr)
        self.assertNotEqual(cclient.connect_ex(self.addr), 0)
        self.assertEqual(cclient.getpeername(), self.addr)
        cclient.close()
        self.printout(cclient)

    def test_Clients(self, username='mock_client', verbose=True):
        """ # fabular.client.Clients """
        csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        args = {username: csocket}
        if verbose:
            self.printf(args)
        clients = fclt.Clients(**args)
        clients[username] = csocket
        clients.address[username] = self.addr
        clients.secret[username] = Secrets.random(file_id='server')
        clients.is_encrypted[username] = False
        clients.color[username] = 'blue'
        self.assertIsInstance(clients, fclt.Clients)
        for k in ['socket', 'address', 'secret',
                  'is_encrypted', 'color']:
            
            self.assertTrue(hasattr(clients, k))
        self.assertIn(username, clients)
        clients.pop(username)
        self.assertNotIn(username, clients)
        if verbose:
            self.printout(clients)
        return username, clients

    def test_receive(self):
        """ # fabular.client.receive """
        cclient = fclt.connect_server(*self.addr)
        recv_thread = threading.Thread(target=fclt.receive, args=(cclient,))
        recv_thread.start()

    def test_write(self):
        """ # fabular.client.write """
        cclient = fclt.connect_server(*self.addr)
        w_thread = threading.Thread(target=fclt.write, args=(cclient,))
        w_thread.start()


if __name__ == "__main__":

    loader = SequentialTestLoader()
    loader.proto_load(ClientModuleTest)
    loader.run_suites()
