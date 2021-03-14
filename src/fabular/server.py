#!/usr/bin/env python
"""
@author: phdenzel

fabular - server
"""
import sys
import os
import threading
import socket
from pyngrok import ngrok
from fabular.comm import fab_msg, fab_log, query_msg
from fabular.client import Clients
from fabular.crypt import pw_prompt, Secrets
from fabular.utils import assign_color, ansi_map, mkdir_p
from fabular.config import LOCALHOST, PORT
import fabular.config as fc


__all__ = ['init_server', 'broadcast', 'handle', 'handshake', 'main']

clients = Clients()


def init_server(host, port, max_conn=fc.MAX_CONN):
    """
    Initialize server and bind to given address

    Args:
        host <str> - host IP address
        port <int/str> - IP port

    Kwargs:
        max_conn <int> - max. number of connections

    Return:
        server <socket object> - bound server socket
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
        data <bytes/str> - the message to be broadcast

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
                try:
                    clients[username].send(message)
                except Exception as ex:
                    clients.pop(username)
    fab_log(data, verbose_mode=fc.VERBOSE)


def handle(server, client_key):
    """
    Client connection handler

    Args:
        server <socket object> - server socket
        client_key <str> - client connected as USERNAME=client_key

    Kwargs/Return:
        None
    """
    global clients
    while True:
        if client_key not in clients:
            break
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
            fab_log('fabular.server.handle: {}'.format(ex), verbose_mode=1)
            return


def ask_for_username(client, encoding=fc.DEFAULT_ENC):
    """
    Ask client for a valid username

    Args:
        client <socket object> - client socket

    Kwargs:
        encoding <str> - string coding

    Return:
        username <str> - received username
    """
    client.send(query_msg('Q:USERNAME'))
    while True:
        username = client.recv(1024).decode(encoding)
        knowns = known_users()
        if not fc.ALLOW_UNKNOWN and username in knowns:
            break
        elif fc.ALLOW_UNKNOWN and username not in clients:
            break
        else:
            try:
                client.send(query_msg('Q:CHUSERNAME'))
            except BrokenPipeError:
                fab_log('EXIT', username)
                return None
    return username


def known_users(known_users_file='known_users',
                separator=b'\t', encoding=fc.DEFAULT_ENC):
    """
    Get the table of usernames and corresponding public RSA keys

    Args:
        None

    Kwargs:
        known_users_file <str> - filename of known_users
        separator <bytes> - byte-string separator between username and key
        encoding <str> - string coding

    Return:
        known_users <dict> - table of known users
    """
    mkdir_p(fc.RSA_DIR)
    filename = os.path.join(fc.RSA_DIR, known_users_file)
    if os.path.exists(filename):
        known_usrs = {}
        with open(filename, 'rb') as f:
            lines = f.read()
        lines = [l.split(separator) for l in lines.split(b'\n\n') if l]
        usernames = [info[0].decode(encoding) for info in lines]
        keys = [info[1] for info in lines]
        return {u: k for u, k in zip(usernames, keys)}
    else:
        return {}


def add_to_known_users(username, public_key,
                       known_users_file='known_users',
                       separator=b'\t', encoding=fc.DEFAULT_ENC):
    """
    Adds username to known_users file containing table of
    usernames and corresponding public RSA keys

    Args:
        username <str> - username to be added to known_users
        public_key <bytes> - username's public RSA key

    Kwargs:
        known_users_file <str> - filename of known_users
        separator <bytes> - byte-string separator between username and key
        encoding <str> - string coding

    Return:
        state_code <int> - if > 0 username was added to file,
                           otherwise there has been an error
    """
    mkdir_p(fc.RSA_DIR)
    filename = os.path.join(fc.RSA_DIR, known_users_file)
    if os.path.exists(filename):
        usr_table = known_users(known_users_file)
        if username in usr_table \
           and public_key.rstrip() == usr_table[username].rstrip():
            return 1
        elif username in usr_table \
             and public_key.rstrip() != usr_table[username].rstrip():
            return 0
    with open(filename, 'ab') as f:
        if isinstance(username, str):
            username = username.encode(encoding)
        if isinstance(public_key, str):
            public_key = public_key.encode(encoding)
        usr_info = separator.join([username, public_key+b'\n'])
        f.write(usr_info)
    return 2


def encryption_setup(client, secrets=None):
    """
    Set up encryption keys between server and client

    Args:
        client <socket object> - client socket

    Kwargs:
        secrets <Secrets object> - secret keys to be exchanged with client

    Return:
        client_secrets <Secrets object> - necessary keys received from client
        client_status <bytes> - status report from client after encryption setup
        is_encrypted <bool> - client's encryption status
    """
    try:
        client.send(query_msg('Q:PUBKEY'))
        client_pubkey = client.recv(fc.BLOCK_SIZE//2)
        client_secrets = Secrets.from_pubkey(client_pubkey)
        if client_secrets is None or not client_secrets.check_hash():
            pass  # TODO: close client connection
        client_secrets.sesskey = secrets.sesskey
        client.send(query_msg('Q:SESSION_KEY'))  # signal for encrypted server keys
        server_keys = client_secrets.hybrid_encrypt(secrets.keys)
        client_status = client.recv(1024)
        client.send(server_keys)
        encryption_status = client.recv(8)  # get confirmation of encryption setup
        is_encrypted = bool(int(encryption_status))
        return client_secrets, client_status, is_encrypted
    except Exception as ex:
        return None, None, False


def register_user(username, client, address, encryption_flag, client_secrets,
                  encoding=fc.DEFAULT_ENC):
    """
    Add userinfo to user table and current clients if valid

    Args:
        username <str> - username candidate
        client <socket.socket object> - connected client socket
        address <str> - address corresponding to username
        encryption_flag <bool> - client completed encryption setup
        client_secrets <Secrets object> - client's secrets

    Kwargs:
        encoding <str> - string coding

    Return:
        status <int> - status response
    """
    global clients
    if None in [username, client, address, client_secrets]:
        status = 0
    else:
        if fc.ALLOW_UNKNOWN:
            status = add_to_known_users(username, client_secrets.public)
        else:
            key_match = known_users()[username].rstrip() != client_secrets.public.rstrip()
            status = 0 if key_match else 1
        clients[username] = client
        clients.address[username] = address
        clients.secret[username] = client_secrets
        clients.is_encrypted[username] = encryption_flag
        clients.color[username] = assign_color(username, clients.color.values(),
                                               limit=fc.MAX_CONN)
    return status


def handshake(server, secrets=None):
    """
    Server main loop: Accept and set up new incoming connections

    Args:
        server <socket object> - server socket

    Kwargs:
        secrets <Secrets object> - secret keys to be exchanged with client

    Return:
        None
    """
    global clients
    v = dict(verbose_mode=fc.VERBOSE)
    while True:
        try:
            client, address = server.accept()
            fab_log('CONN', address, **v)

            # set up username
            username = ask_for_username(client)
            if username:
                fab_log('USRN', username, **v)

            # encryption handshake
            client_secrets, status, is_encrypted = \
                encryption_setup(client, secrets=secrets)
            if status:
                fab_log(status, verbose_mode=3)

            # add username to user table and current clients
            status = register_user(username, client, address,
                                   is_encrypted, client_secrets)
            if status == 0:
                fab_log('LERR', username)
                known = known_users()
                try:
                    client.send(query_msg('Q:KILL'))
                    client.close()
                except BrokenPipeError:
                    pass
                continue

            # announce entry of user
            client.send(query_msg('Q:ACCEPT'))
            try:
                fab_log(client.recv(256), verbose_mode=3)
                broadcast(fab_msg('ENTR', username))
            except UnicodeDecodeError:
                pass

            handle_thread = threading.Thread(target=handle, args=(server, username,))
            handle_thread.daemon = True
            handle_thread.start()

        except KeyboardInterrupt:
            fab_log('ENDS', verbose_mode=3)
            return


def main(host=LOCALHOST, port=PORT):
    """
    Start a listening server and handle incoming connections

    Args:
        None

    Kwargs:
        host <str> - host IP address
        port <int/str> - IP port

    Return:
        None
    """
    global clients

    try:
        # Name definitions
        file_id = input('Session name: ')
        if not file_id:
            file_id = 'server'
        pw = pw_prompt(confirm=True)
        # RSA keys
        server_secrets = Secrets.random(file_id='server')
        server_secrets.pw = pw
        if not server_secrets.check_hash():
            sys.exit()

        # Set up server socket
        clients = Clients()
        server = init_server(host, port, max_conn=16)
        fab_log('INIS', verbose_mode=3)

        # open ngrok tunnel
        tunnel = ngrok.connect(fc.PORT, "tcp")
        public_addr = tunnel.public_url
        pub_host, pub_port = public_addr.split(':')[1:]
        pub_host = pub_host[2:]
        fab_log(f"Opened tunnel @ --host {pub_host} --port {pub_port}...",
                verbose_mode=3)

        # start accept thread
        accept_thread = threading.Thread(target=handshake, args=(server, server_secrets,))
        accept_thread.daemon = True
        accept_thread.start()
        accept_thread.join()
    except KeyboardInterrupt:
        fab_log('ENDS', verbose_mode=3)


if __name__ == "__main__":

    # main()

    from tests.prototype import SequentialTestLoader
    from tests.server_test import ServerModuleTest
    loader = SequentialTestLoader()
    loader.proto_load(ServerModuleTest)
    loader.run_suites()
