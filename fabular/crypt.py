#!/usr/bin/env python
"""
fabular - crypt

@author: phdenzel
"""
import os
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from fabular.comm import fab_log
from fabular.utils import mkdir_p
import fabular.config as fc


def generate_RSAk(size=fc.RSA_bits,
                  export_id='id',
                  export_dir='.fabular/rsa'):
    """
    Generate a RSA key for server-client handshake,
    from file if it exists or from a random number

    Args:
        None

    Kwargs:
        size <int> - byte size of the key

    Return:
        public, private <bytes> - public/private RSA key
    """
    pubfile = os.path.join(export_dir, export_id+'_rsa.pub')
    privfile = os.path.join(export_dir, export_id+'_rsa')
    mkdir_p(export_dir)
    if os.path.exists(pubfile) and os.path.exists(privfile):
        with open(pubfile, 'rb') as f:
            public = RSA.importKey(f.read()).exportKey(format='PEM')
        with open(privfile, 'rb') as f:
            private = RSA.importKey(f.read()).exportKey(format='PEM')
    else:
        random = Random.new().read
        RSAkey = RSA.generate(size, random)
        public = RSAkey.publickey().exportKey(format='PEM')
        private = RSAkey.exportKey(format='PEM')
        with open(pubfile, 'wb') as f:
            f.write(public)
        with open(privfile, 'wb') as f:
            f.write(private)
    return public, private


def session_keys(block_size=8):
    """
    Create a session key and hash from a number of random bits

    Args:
        None

    Kwargs:
        byte_size <int> - number of bytes

    Return:
        rand, hash <bytes> - sequence of random bits and corresponding hash

    Note:
        if AES encryption cipher is used, byte_size should be
    """
    rand8 = os.urandom(block_size)
    hash8 = get_hash(rand8)
    return rand8, hash8


def get_hash(key, encoding=fc.DEFAULT_ENC):
    """
    Calculate MD5 hash of a given key

    Args:
        key <bytes> - a (public) key

    Kwargs:
        encoding <str> - string coding

    Return:
        hash_key <bytes> - corresponding hash
    """
    if isinstance(key, str):
        key = key.encode(encoding)
    hash_key = hashlib.md5(key).hexdigest().encode(encoding)
    return hash_key


def check_hash(key, hash_key, encoding=fc.DEFAULT_ENC):
    """
    Comparison of a (public) key's hash to a given hash key

    Args:
        key <bytes> - an encoded (public) key
        hash_key <bytes> - a hash key

    Kwargs:
        encoding <str> - string coding

    Return:
        check <bool> - True if both hashes agree
    """
    hash_pub = hashlib.md5(key).hexdigest().encode(encoding)
    return hash_pub == hash_key


def block_pad(msg, block_size=AES.block_size, encoding=fc.DEFAULT_ENC):
    """
    Wrapper for padding a unencoded message

    Args:
        msg <str> - TODO

    Kwargs:
        block_size <int> - TODO
        encoding <str> - string coding

    Return:
        msg_pad <bytes> - TODO
    """
    if isinstance(msg, str):
        msg = msg.encode(encoding)
    return pad(msg, block_size)


def block_unpad(msg, block_size=AES.block_size, encoding=fc.DEFAULT_ENC):
    """
    Wrapper for unpadding a decoded message

    Args:
        msg <str/bytes> - TODO

    Kwargs:
        block_size <int> - TODO
        encoding <str> - string coding

    Return:
        msg_unpad <str> - TODO
    """
    msg_unpad = unpad(msg, block_size)
    if isinstance(msg_unpad, bytes):
        msg_unpad = msg_unpad.decode(encoding)
    return msg_unpad


def AES_from_key(key, encoding=fc.DEFAULT_ENC):
    """
    Create an AES cipher from a key

    Args:
        key <bytes> - TODO

    Kwargs:
        encoding <str> - string coding

    Return:
        cipher <Crypto.Cipher object> - TODO
    """
    if isinstance(key, str):
        key = key.encode(encoding)
    if len(key) == 8:
        key2 = key + key[::-1]
    elif len(key) == 16:
        key2 = key
    else:
        fab_log('AES requires a cipher key of length of N16!', verbose_mode=5)
        return
    AES_cipher = AES.new(key2, AES.MODE_CBC, IV=key2)
    return AES_cipher


def encrypt_msg(message, key=None, **kwargs):
    """
    Encrypt a message using AES cipher

    Args:
        message <str> - message to be encrypted

    Kwargs:
        key <bytes> - TODO
        block_size <int> - TODO
        encoding <str> - string coding

    Return:
        msg_enc <bytes> - encrypted message
    """
    if not message:
        return message
    message = block_pad(message, **kwargs)
    if key is None:
        fab_log('Encryption requires a cipher key!', verbose_mode=4)
        return
    cipher = AES_from_key(key)
    msg_enc = cipher.encrypt(message)
    return msg_enc


def decrypt_msg(message, key=None, **kwargs):
    """
    Decrypt a message using AES cipher

    Args:
        message <bytes> - message to be decrypted

    Kwargs:
        key <bytes> - TODO
        block_size <int> - TODO
        encoding <str> - string coding

    Return:
        msg_dec <bytes> - decrypted message
    """
    if not message:
        return message
    if key is None:
        fab_log('Decryption requires a cipher key!', verbose_mode=4)
        return
    cipher = AES_from_key(key)
    msg_dec = cipher.decrypt(message)
    msg_dec = block_unpad(msg_dec, **kwargs)
    return msg_dec


class Secrets(object):
    """
    Simple data structure which holds secrets
    """
    def __init__(self):
        pass


if __name__ == "__main__":
    pub, priv = generate_RSAk(export_id='server')
    # hashpub = get_hash(pub)
    print(pub)
    # print(hashpub)
    # print(check_hash(pub, hashpub))
    print(priv)

    rand8, hash8 = session_keys()
    print(rand8)
    print(hash8)
    print(check_hash(rand8, hash8))

    cipher = AES_from_key(rand8)
    print(len(rand8), len(rand8 + rand8[::-1]))
    print(cipher)
    print(cipher.block_size, AES.block_size)

    test_msg = "Eureka! Encrypt/Decrypt success!"
    msg_enc = encrypt_msg(test_msg, key=rand8)
    msg_dec = decrypt_msg(msg_enc, rand8)
    print(msg_enc)
    print(msg_dec)
