#!/usr/bin/env python
"""
@author: phdenzel

fabular - client
"""
import sys
import socket
import threading
from fabular.comm import fab_log, is_query, cmd_signals
from fabular.crypt import pw_prompt, Secrets
from fabular.config import HOST, PORT
import fabular.config as fc

if HOST is None:
    HOST = fc.LOCALHOST


__all__ = ['Clients', 'connect_server', 'receive', 'write', 'main']

accepted = False
decode = False
stop_threads = False
username = ""
client_secrets = None


class Clients(object):
    """
    Data structure for holding client information
    """
    def __init__(self, **kwargs):
        """
        Initializes empty tables for sockets, addresses, secrets,
        encyption flags, and username color

        Args/Kwargs:
            None
        """
        self.socket = {}
        self.address = {}
        self.secret = {}
        self.is_encrypted = {}
        self.color = {}

    def __getitem__(self, key):
        """
        Get value of socket table from key

        Args:
            key <str> - username of the client

        Kwargs:
            None

        Return:
            socket <socket.socket object> - username's client socket
        """
        return self.socket[key]

    def __setitem__(self, key, val):
        """
        Set value of socket table at key

        Args:
            key <str> - username of the client
            val <socket.socket object> - username's client socket

        Kwargs/Return:
            None
        """
        self.socket[key] = val

    def __iter__(self):
        """
        Iterator for client-socket table

        Args/Kwargs:
            None

        Return:
            iterator <dict.__iter__> - socket iterator
        """
        return self.socket.__iter__()

    def __contains__(self, key):
        """
        Check if username is in the table

        Args:
            key <str> - username of the client

        Kwargs:
            None

        Return:
            contains <bool> - True if username in table
        """
        return self.socket.__contains__(key)

    def pop(self, key):
        """
        Pop username from all tables and return the removed socket

        Args:
            key <str> - username of the client

        Kwargs:
            None

        Return:
            socket <socket.socket object> - username's client socket
        """
        socket = None
        if key in self.socket:
            socket = self.socket.pop(key)
        if key in self.address:
            self.address.pop(key)
        if key in self.secret:
            self.secret.pop(key)
        if key in self.is_encrypted:
            self.is_encrypted.pop(key)
        if key in self.color:
            self.color.pop(key)
        return socket


def connect_server(host, port):
    """
    Initialize socket and connect to server address

    Args:
        host <str> - host IP address
        port <int/str> - IP port

    Kwargs:
        None

    Return:
        client <socket.socket object> - client socket
    """
    if not isinstance(port, int):
        port = int(port)
    address = (host, port)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(address)
    return client


def receive(client):
    """
    Message recipience loop; handles special keys and reacts accordingly

    Args:
        client <socket.socket object> - client socket

    Kwargs/Return:
        None
    """
    global username, client_secrets, accepted, decode, stop_threads
    while True:
        if stop_threads:
            break
        try:
            message = client.recv(fc.BLOCK_SIZE)
            if message:
                if is_query(message, 'Q:USERNAME'):
                    client.send(username.encode(fc.DEFAULT_ENC))
                elif is_query(message, 'Q:CHUSERNAME'):
                    fab_log('CUSR', verbose_mode=3)
                    username = input('Enter another username: ')
                    client.send(username.encode(fc.DEFAULT_ENC))
                elif is_query(message, 'Q:PUBKEY'):
                    client.send(client_secrets.pubkey)
                elif is_query(message, 'Q:SESSION_KEY'):
                    if fc.ENCRYPTION:
                        client.send(f'{username}: Setting up encryption...'.encode(fc.DEFAULT_ENC))
                        fab_log('DCRY', verbose_mode=3)
                        enc_msg = client.recv(2*fc.BLOCK_SIZE)
                        server_keys = client_secrets.hybrid_decrypt(enc_msg)
                        server_secrets = Secrets.from_keys(server_keys)
                        if server_secrets is not None:
                            client_secrets.sesskey = server_secrets.sesskey
                            decode = True
                            client.send(b'1')
                        else:
                            fab_log('FDCR', verbose_mode=3)
                            client.send(b'0')
                    else:
                        client.send(f'{username}: Proceed without encryption'.encode(
                            fc.DEFAULT_ENC))
                        client.recv(2*fc.BLOCK_SIZE)
                        server_secrets = Secrets()
                        client.send(b'0')
                elif is_query(message, 'Q:ACCEPT'):
                    client.send(f'{username}: Starting Thread(write)...'.encode(fc.DEFAULT_ENC))
                    fab_log('WRYT', verbose_mode=3)
                    fab_log('', verbose_mode=3)
                    accepted = True
                elif is_query(message, 'Q:KILL'):
                    fab_log('LERR', verbose_mode=3)
                    accepted = False
                    stop_threads = True
                else:
                    if decode:
                        message = client_secrets.AES_decrypt(message)
                    fab_log(message)
        except Exception as ex:
            fab_log('fabular.client.receive: {}'.format(ex), verbose_mode=5)
            stop_threads = True
            client.close()
            break


def write(client):
    """
    Message transmission loop which handles transmissions and logoff keys.
    Triggers when <stop_threads> is False and <accepted> is True

    Args:
        client <socket.socket object> - client socket

    Kwargs/Return:
        None
    """
    global stop_threads

    while True:
        if stop_threads:
            break
        if not accepted:
            continue
        message = input("\033[1A")
        if message:
            if any([s in message.lower() for s in cmd_signals['X']]):
                stop_threads = True
            if decode:
                message = client_secrets.AES_encrypt(message.encode(fc.DEFAULT_ENC))
            else:
                message = message.encode(fc.DEFAULT_ENC)
            client.send(message)


def main():
    """
    Connect to server socket and start receive/write thread

    Args/Kwargs/Return:
        None
    """
    global username, client_secrets, accepted, decode, stop_threads

    accepted = False
    decode = False
    stop_threads = False

    # Name definitions
    username = input('Enter your username: ')
    pw = pw_prompt(confirm=True)

    # RSA keys
    client_secrets = Secrets.from_RSA_fileID(f'{username}', password=pw)
    client_secrets.pw = pw
    if not client_secrets.check_hash():
        sys.exit()

    # login to server
    client = connect_server(HOST, PORT)

    receive_thread = threading.Thread(target=receive, args=(client,))
    # receive_thread.daemon = True
    receive_thread.start()

    write_thread = threading.Thread(target=write, args=(client,))
    # receive_thread.daemon = True
    write_thread.start()


if __name__ == "__main__":

    # main()

    from tests.prototype import SequentialTestLoader
    from tests.client_test import ClientModuleTest
    loader = SequentialTestLoader()
    loader.proto_load(ClientModuleTest)
    loader.run_suites()
