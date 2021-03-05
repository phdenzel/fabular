"""
fabular - tests.server_test

@author: phdenzel
"""
import time
import socket
import threading
import fabular.config as fc
import fabular.server as fsrvr
from fabular.client import Clients
from fabular.crypt import Secrets
from tests.prototype import UnitTestPrototype
from tests.prototype import SequentialTestLoader


class ServerModuleTest(UnitTestPrototype):

    port = 65333

    def setUp(self):
        # arguments and keywords
        self.port += 1
        self.msg = ("I've wrestled with an alligator, "
                    "I done tussle with a whale, "
                    "I done handcuffed lightnin'"
                    "and thrown thunder in jail."
                    "Only last week I murdered a rock, "
                    "injured a stone, hospitalized a brick. "
                    "I'm so mean, I make medicine sick.")
        try:
            self.server = fsrvr.init_server(*self.addr)
        except OSError:
            pass
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

    @property
    def addr(self):
        return ('127.0.0.1', self.port)

    def mock_clients(self, username='mock_client'):
        clients = Clients()
        clients[username] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.address[username] = self.addr
        clients.secret[username] = Secrets.random(file_id='server')
        clients.is_encrypted[username] = False
        clients.color[username] = 'blue'
        return username, clients

    def test_init_server(self):
        """ # fabular.server.init_server """
        args = '127.0.0.1', 65444
        self.printf(args)
        server = fsrvr.init_server(*args)
        self.assertIsInstance(server, socket.socket)
        self.assertEqual(server.getsockname()[0], args[0])
        self.assertEqual(server.getsockname()[1], int(args[1]))
        # !=0: not connected
        self.assertNotEqual(server.connect_ex((args[0], int(args[1]))), 0)
        self.printout(server)
        server.close()

    def test_broadcast(self):
        """ # fabular.server.broadcast """
        self.printf(self.msg)
        username, clients = self.mock_clients()
        clients[username].connect(self.addr)
        fsrvr.broadcast(self.msg)

    def test_handle(self):
        """ # fabular.server.handle """
        username, clients = self.mock_clients()
        self.printf(username)
        # client_secrets = clients.secret[username]
        clients[username].connect(self.addr)
        fsrvr.clients = clients
        thread = threading.Thread(target=fsrvr.handle,
                                  args=(self.server, username,))
        thread.daemon = True
        thread.start()
        clients[username].send(self.msg.encode('utf-8'))
        print("\nNo errors occurred...\n")

    def test_handshake(self, delay=False):
        """ # fabular.server.handshake """
        print("Handshake thread with mock client started...")
        username, clients = self.mock_clients()
        client_secrets = clients.secret[username]
        clients[username].connect(self.addr)
        thread = threading.Thread(target=fsrvr.handshake,
                                  args=(self.server, client_secrets))
        thread.daemon = True
        thread.start()
        clients[username].recv(2048)  # Q:USERNAME
        clients[username].send(username.encode('utf-8'))
        clients[username].recv(2048)  # Q:PUBKEY
        clients[username].send(clients.secret[username].pubkey)
        clients[username].recv(2048)  # Q:SESSION_KEY
        clients[username].send(b'Encryption handshake...')
        clients[username].recv(2048)  # Encrypted response
        clients[username].send(b'0')
        clients[username].recv(2048)  # Q:ACCEPT
        clients[username].send(b'Starting chat thread...')
        clients[username].recv(2048)
        clients[username].send(b'\\leave')
        clients[username].recv(2048)
        print("\nNo errors occurred...\n")


if __name__ == "__main__":

    loader = SequentialTestLoader()
    loader.proto_load(ServerModuleTest)
    loader.run_suites()
