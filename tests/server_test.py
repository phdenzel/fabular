"""
fabular - tests.server_test

@author: phdenzel
"""
import os
import signal
import socket
import threading
from tests.prototype import UnitTestPrototype, SequentialTestLoader
from fabular import config as fc
import fabular.server as fsrvr
from fabular.client import Clients
from fabular.crypt import Secrets


class ServerModuleTest(UnitTestPrototype):

    def setUp(self):
        # arguments and keywords
        self.addr = ('127.0.0.1', 65333)
        self.msg = ("I done wrestled with an alligator, "
                    "I done tussled with a whale, "
                    "I done handcuffed lightnin'"
                    "and thrown thunder in jail."
                    "Only last week I murdered a rock, "
                    "injured a stone, hospitalized a brick. "
                    "I'm so mean, I make medicine sick.")
        # self.v = {'verbose': 3}
        self.server = fsrvr.init_server(*self.addr)
        print("")
        print(self.separator)
        print(self.shortDescription())

    def tearDown(self):
        try:
            self.server.close()
        except AttributeError:
            pass
        print("")

    def mock_clients(self, username='mock_client'):
        clients = Clients()
        clients[username] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.address[username] = self.addr
        clients.secret[username] = Secrets.random(export_id='server')
        clients.is_encrypted[username] = False
        clients.color[username] = 'blue'
        return username, clients

    def test_server_init_server(self):
        """ # fabular.server.init_server """
        args = '127.0.0.1', 65444
        self.printf(args)
        server = fsrvr.init_server(*args)
        self.assertIsInstance(server, socket.socket)
        self.assertEqual(server.getsockname()[0], args[0])
        self.assertEqual(server.getsockname()[1], int(args[1]))
        self.assertNotEqual(server.connect_ex((args[0], int(args[1]))), 0)  # !=0: not connected
        self.printout(server)
        server.close()

    def test_server_broadcast(self):
        """ # fabular.server.broadcast """
        self.printf(self.msg)
        username, clients = self.mock_clients()
        clients[username].connect(self.addr)
        fsrvr.broadcast(self.msg)

    def test_server_handle(self):
        """ # fabular.server.handle """
        self.printf(self.msg)
        username, clients = self.mock_clients()
        clients[username].connect(self.addr)
        thread = threading.Thread(target=fsrvr.handle, args=(username,))
        thread.daemon = True
        thread.start()
        clients[username].send(self.msg)
        

    def test_server_handshake(self, delay=False):
        """ # fabular.server.handshake """
        print("Handshake thread with mock client started...")
        username, clients = self.mock_clients()
        client_secrets = clients.secret[username]
        clients[username].connect(self.addr)
        thread = threading.Thread(target=fsrvr.handshake, args=(self.server, client_secrets))
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
        clients[username].close()
        self.server = None

    def test_server_handle(self):
        """ # fabular.server.handle """
        pass


if __name__ == "__main__":
    loader = SequentialTestLoader()
    loader.proto_load(ServerModuleTest)
    loader.run_suites()
    
    # os.kill(os.getpid(), signal.SIGKILL)
    
    
