#!/usr/bin/env python
"""
fabular - server

@author: phdenzel

TODO:
    - fix for clean exit
    - investigate CPU spike after client exit
"""
import sys
import threading
import socket
from fabular.comm import fab_msg
from fabular.comm import fab_log
from fabular.comm import query_msg
from fabular.client import Clients
from fabular.crypt import generate_RSAk, session_keys
from fabular.crypt import get_hash
from fabular.crypt import Secrets
from fabular.utils import assign_color, ansi_map
from fabular.config import HOST
from fabular.config import PORT
import fabular.config as fc
if HOST is None:
    HOST = fc.LOCALHOST


def init_server(host, port, max_conn=fc.MAX_CONN):
    """
    Initialize server and bind to given address

    Args:
        host <str> - host IP address
        port <int> - IP port

    Kwargs:
        max_conn <int> - max. number of connections

    Return:
        server <socket.Socket object> - bound server socket
    """
    if not isinstance(port, int):
        port = int(port)
    address = (host, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen(max_conn)
    return server


def broadcast(data):
    """
    Broadcast a message to all clients

    Args:
        message <str> - the message to be broadcast

    Kwargs/Return:
        None
    """
    if isinstance(data, str):
        data = data.encode(fc.DEFAULT_ENC)
    for username in clients:
        if clients[username]:
            if clients.is_encrypted[username]:
                message = clients.secret[username].AES_encrypt(data)
            else:
                message = data
            clients[username].send(message)
    fab_log(data, verbose_mode=fc.VERBOSE)


def handle(client_key):
    """
    Client connection handler

    Args:
        client_key <str> - client connected as USERNAME=client_key

    Kwargs/Return:
        None
    """
    while True:
        try:
            data = clients[client_key].recv(1024)
            if data:
                if clients.is_encrypted[client_key]:
                    message = clients.secret[client_key].AES_decrypt(data)
                else:
                    message = data.decode(fc.DEFAULT_ENC)
                message = fab_msg('CHAT', message,
                                  prefix='{}{}>{} '.format(ansi_map[clients.color[client_key]],
                                                           client_key, ansi_map['reset']),
                                  suffix='')
                broadcast(message)
        except Exception as ex:
            client = clients.pop(client_key)
            if client:
                client.close()
                exit_msg = fab_msg('EXIT', client_key)
                broadcast(exit_msg)
            fab_log('fabular.server.handle: {}'.format(ex), verbose_mode=5)
            break


def handshake(secrets=None):
    """
    Server main loop: Accept and set up new incoming connections

    Args:
        keys <dict> - a table of keys for encryption handshake

    Kwargs/Return:
        None
    """
    v = dict(verbose_mode=fc.VERBOSE)
    while True:
        try:
            client, address = server.accept()
            fab_log('CONN', address, **v)

            # set up username
            client.send(query_msg('Q:USERNAME'))
            while True:
                username = client.recv(1024).decode(fc.DEFAULT_ENC)
                if username not in clients:
                    break
                else:
                    client.send(query_msg('Q:CHUSERNAME'))
            fab_log('USRN', username, **v)

            # encryption handshake
            client.send(query_msg('Q:PUBKEY'))
            client_pubkey = client.recv(fc.BLOCK_SIZE//2)
            client_secrets = Secrets.from_pubkey(client_pubkey)
            if client_secrets is None or not client_secrets.check_hash():
                pass  # close client connection
            client_secrets.sesskey = secrets.sesskey
            client.send(query_msg('Q:SESSION_KEY'))  # signal for encrypted server keys
            server_keys = client_secrets.hybrid_encrypt(secrets.keys)
            status = client.recv(1024)
            fab_log(status, verbose_mode=3)
            client.send(server_keys)
            status = client.recv(8)  # get confirmation of encryption setup
            is_encrypted = bool(int(status))

            # add username to table
            clients[username] = client
            clients.address[username] = address
            clients.secret[username] = client_secrets
            clients.is_encrypted[username] = is_encrypted
            clients.color[username] = assign_color(username, clients.color.values(),
                                                   limit=fc.MAX_CONN)

            # announce entry of user
            client.send(query_msg('Q:ACCEPT'))
            fab_log(client.recv(256), verbose_mode=3)
            broadcast(fab_msg('ENTR', username))  # TODO: first failure of encryption
            handle_thread = threading.Thread(target=handle, args=(username,))
            handle_thread.start()

        except KeyboardInterrupt:
            fab_log('ENDS', verbose_mode=3)
            return


if __name__ == "__main__":

    # RSA keys
    pub, priv = generate_RSAk(export_id='server')
    hashpub = get_hash(pub)
    key8, hash8 = session_keys()
    secrets = Secrets(priv, pub, hashpub, key8, hash8)
    if not secrets.check_hash():
        sys.exit()

    # Set up server socket
    clients = Clients()
    server = init_server(HOST, PORT, max_conn=16)
    fab_log('INIS', verbose_mode=3)

    # start accept thread
    accept_thread = threading.Thread(target=handshake, args=(secrets,))
    accept_thread.start()
    accept_thread.join()
    server.close()
