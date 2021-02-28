#!/usr/bin/env python
"""
fabular - client

@author: phdenzel
"""
# import sys
import socket
import threading
import fabular.config as fc
from fabular.config import HOST
from fabular.config import PORT
from fabular.comm import fab_log
from fabular.comm import is_query
if HOST is None:
    HOST = fc.LOCALHOST


stop_threads = False


class Clients(object):
    def __init__(self, *args):
        self.socket = {}
        self.address = {}
        self.secret = {}

    def __getitem__(self, key):
        return self.socket[key]

    def __setitem__(self, key, val):
        self.socket[key] = val

    def __iter__(self):
        return self.socket.__iter__()

    def __next__(self):
        return self.socket.__next__()

    def pop(self, key):
        socket = self.socket.pop(key)
        self.address.pop(key)
        self.secret.pop(key)
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


def receive():
    """
    TODO
    """
    global stop_threads
    while True:
        if stop_threads:
            break
        try:
            message = client.recv(1024)
            if message:
                if is_query(message, 'Q:USERNAME'):
                    client.send(username.encode(fc.DEFAULT_ENC))
                elif is_query(message, 'Q:KILL'):
                    pass
                else:
                    print(message.decode(fc.DEFAULT_ENC))
        except Exception as ex:
            fab_log('client.receive() encountered an error!\n'+ex.message, 5)
            stop_threads = True
            client.close()
            break


def write():
    """
    TODO
    """
    while True:
        if stop_threads:
            break
        message = input("")
        client.send(message.encode(fc.DEFAULT_ENC))


if __name__ == "__main__":

    username = input('Enter your username: ')
    
    client_socket = connect_server(HOST, PORT)
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()

    # receive_thread.join()
    # write_thread.join()
