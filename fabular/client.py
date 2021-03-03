#!/usr/bin/env python
"""
fabular - client

@author: phdenzel
"""
import sys
import socket
import threading
import fabular.config as fc
from fabular.config import HOST
from fabular.config import PORT
from fabular.comm import fab_log
from fabular.comm import is_query
from fabular.comm import cmd_signals
from fabular.crypt import generate_RSAk
from fabular.crypt import get_hash
from fabular.crypt import Secrets
if HOST is None:
    HOST = fc.LOCALHOST


__all__ = ['Clients', 'connect_server', 'receive', 'write', 'main']

accepted = False
decode = False
stop_threads = False
username = ""
client_secrets = None


class Clients(object):
    def __init__(self, *args):
        self.socket = {}
        self.address = {}
        self.secret = {}
        self.is_encrypted = {}
        self.color = {}

    def __getitem__(self, key):
        return self.socket[key]

    def __setitem__(self, key, val):
        self.socket[key] = val

    def __iter__(self):
        return self.socket.__iter__()

    def __contains__(self, key):
        return self.socket.__contains__(key)

    def pop(self, key):
        socket = self.socket.pop(key)
        self.address.pop(key)
        self.secret.pop(key)
        self.is_encrypted.pop(key)
        self.color.pop(key)
        return socket


def connect_server(host, port):
    """
    Initialize socket and connect to server address

    Args:
        host <str> - host IP address
        port <int> - IP port

    Kwargs:
        None

    Return:
        client <socket.Socket object> - client socket
    """
    if not isinstance(port, int):
        port = int(port)
    address = (host, port)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(address)
    return client


def receive(client):
    """
    TODO
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
                    pass
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
    TODO
    """
    global stop_threads

    while True:
        if stop_threads:
            break
        if not accepted:
            continue
        message = input("\033[1A")
        if message:
            if any([s in message.lower() for s in cmd_signals['Q']]):
                stop_threads = True
            if decode:
                message = client_secrets.AES_encrypt(message.encode(fc.DEFAULT_ENC))
            else:
                message = message.encode(fc.DEFAULT_ENC)
            client.send(message)


def main():
    global username, client_secrets, accepted, decode, stop_threads

    accepted = False
    decode = False
    stop_threads = False
    username = input('Enter your username: ')

    # RSA keys
    pub, priv = generate_RSAk(export_id=f'{username}')
    hash_pub = get_hash(pub)
    client_secrets = Secrets(private=priv, public=pub, public_hash=hash_pub)
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

    main()
