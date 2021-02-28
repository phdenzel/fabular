#!/usr/bin/env python
"""
fabular - server

@author: phdenzel

Strategy:
  1) Generate RSA key pairs and public hash.
     If newly generated, save them in files .fabular/rsa/id_rsa.pub and id_rsa
     > generate_RSAk(pub, priv)
  3) Generate session key and hash
     > session_keys()
  4) Set up server socket
     > init_server()
  5) Start handshake thread
     > threading.Thread(target=handshake)
  6) In handshake thread:
     Accept new connection iff
        - unique username is given
        - TODO
"""
import sys
import threading
import socket
import fabular.config as fc
from fabular.config import HOST
from fabular.config import PORT
from fabular.comm import fab_msg, fab_log
from fabular.comm import query_msg
from fabular.client import Clients
from fabular.crypt import generate_RSAk, session_keys
from fabular.crypt import get_hash, check_hash
# from fabular.crypt import encrypt_msg
# from fabular.crypt import decrypt_msg
if HOST is None:
    HOST = fc.LOCALHOST


def init_server(host, port, max_conn=16):
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


def broadcast(message):
    """
    Broadcast a message to all clients

    Args:
        message <str> - the message to be broadcast

    Kwargs/Return:
        None
    """
    if isinstance(message, str):
        message = message.encode(fc.DEFAULT_ENC)
    for client in clients.values():
        if client:
            client.send(message)
    fab_log(message, verbose_mode=fc.VERBOSE)


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
            message = clients[client_key].recv(1024)
            # decode message here
            if message:
                message = fab_msg('CHAT', message.decode(fc.DEFAULT_ENC),
                                  prefix=f'{client_key}> ', suffix='')
                broadcast(message)
        except Exception as ex:
            client = clients.pop(client_key)
            if client:
                client.close()
                exit_msg = fab_msg('EXIT', client_key)
                broadcast(exit_msg)
            fab_log(ex.message, verbose_mode=5)
            break


def handshake(keys=None):
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
            # set up username
            while True:
                client.send(query_msg('Q:USERNAME'))
                fab_log('CONN', address, **v)
                username = client.recv(1024).decode(fc.DEFAULT_ENC)
                if username not in clients:
                    break
                else:
                    chusr_msg = fab_msg('CUSR')
                    client.send(chusr_msg)
            # encryption handshake
            key = keys['RSA.pub'] + b':' + keys['RSA.hash']
            
            # server.send()
            # if fc.RSA_bits >= 8192:
            # add username to list
            clients[username] = client
            # announce entry of user
            fab_log('USRN', username, **v)
            broadcast(fab_msg('ENTR', username))
            handle_thread = threading.Thread(target=handle, args=(username,))
            handle_thread.start()
        except KeyboardInterrupt:
            fab_log('ENDS', verbose_mode=3)
            return


if __name__ == "__main__":
    import shutil
    shutil.rmtree('.fabular', ignore_errors=True)
    # RSA keys
    pub, priv = generate_RSAk(fc.RSA_bits, export_id='server')
    key8, hash8 = session_keys()
    keys = {
        'RSA.pub': pub,
        'RSA.priv': priv,
        'RSA.hash': get_hash(pub),
        'session64': key8,
        'hash64': hash8
    }
    print(len(pub), len(priv))
    print(len(pub), len(get_hash(pub)))
    print(len(key8), len(hash8))

    # Set up server socket
    server = init_server(HOST, PORT, max_conn=16)
    print(server)
    clients = Clients()

    sys.exit()

    fab_log('INIS', verbose_mode=3)

    accept_thread = threading.Thread(target=handshake, args=())
    accept_thread.start()
    accept_thread.join()
    server.close()
