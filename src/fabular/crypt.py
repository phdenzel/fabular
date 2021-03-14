#!/usr/bin/env python
"""
@author: phdenzel

fabular - crypt
"""
import os
import getpass
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
from cryptography.hazmat.primitives import serialization, hashes, ciphers
from cryptography.hazmat.primitives import padding as sym_pad
from cryptography.fernet import Fernet
from fabular.comm import fab_log
from fabular.utils import mkdir_p
import fabular.config as fc


CCSEQ = b':::'  # concat sequence


def pw_prompt(confirm=True):
    """
    Trigger prompt to input a password phrase with an optional confirmation step

    Args:
        None

    Kwargs:
        confirm <bool> - add a confirmation step

    Return:
        pw <bytes> - password input
    """
    pw = getpass.getpass(prompt='Passphrase: ',
                         stream=None).encode(fc.DEFAULT_ENC)
    if confirm:
        pw2 = getpass.getpass(prompt='Confirm passphrase: ',
                              stream=None).encode(fc.DEFAULT_ENC)
        if pw != pw2:
            raise OSError("Passwords don't match!")
    if pw:
        return pw
    return None


def generate_RSAk(size=fc.BLOCK_SIZE,
                  password=None,
                  file_id='id',
                  file_dir=fc.RSA_DIR):
    """
    Generate a RSA key for server-client handshake,
    from file if it exists or from a random number

    Args:
        None

    Kwargs:
        size <int> - byte size of the key
        password <bytes> - optional password
        file_id <str> - file prefix, e.g. user-id
        file_dir <str> - target directory; [default: .fabular/rsa/]

    Return:
        public, private <bytes> - public/private RSA key
    """
    pubfile = ""
    privfile = ""
    if file_id is not None and file_dir is not None:
        pubfile = os.path.join(file_dir, file_id+'_rsa.pub')
        privfile = os.path.join(file_dir, file_id+'_rsa')
        mkdir_p(file_dir)
    phrase = serialization.BestAvailableEncryption(password) \
        if password else serialization.NoEncryption()

    if os.path.exists(pubfile) and os.path.exists(privfile):
        with open(pubfile, 'rb') as f:
            pubkey = serialization.load_pem_public_key(f.read())
            public = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1)
        with open(privfile, 'rb') as f:
            privkey = serialization.load_pem_private_key(f.read(), password)
            private = privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=phrase)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size)
        private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=phrase)
        public_key = private_key.public_key()
        public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1)
        if pubfile:
            with open(pubfile, 'wb') as f:
                f.write(public)
        if privfile:
            with open(privfile, 'wb') as f:
                f.write(private)
    return public, private


def RSA_from_key(data, password=None, encoding=fc.DEFAULT_ENC):
    """
    RSA cipher instance from the byte data

    Args:
        data <bytes> - public/private byte data

    Kwargs:
        password <bytes> - optional password
        encoding <str> - string coding

    Return:
        cipher <cryptography.hazmat.RSAKey object> - RSA cipher
    """
    if isinstance(data, str):
        data = data.encode(fc.DEFAULT_ENC)
    if b'PRIVATE' in data:
        cipher = serialization.load_pem_private_key(data, password)
    else:
        cipher = serialization.load_pem_public_key(data)
    return cipher


def RSA_encrypt(message, cipher, encoding=fc.DEFAULT_ENC):
    """
    Use a (public) RSA cipher to encrypt a message

    Args:
        message <bytes> - message to be encrypted
        cipher <cryptography.hazmat.RSAKey object> - encryption cipher

    Kwargs:
        encoding <str> - string coding

    Return:
        enc_msg <bytes> - encrypted message
    """
    if isinstance(message, str):
        message = message.encode(encoding)
    enc_msg = cipher.encrypt(
        message,
        asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(),
                      label=None))
    return enc_msg


def RSA_decrypt(enc_msg, cipher, encoding=fc.DEFAULT_ENC):
    """
    Use a (private) RSA cipher to decrypt a message

    Args:
        enc_msg <bytes> - message to be decrypted
        cipher <cryptography.hazmat.RSAKey object> - decryption cipher

    Kwargs:
        encoding <str> - string coding

    Return:
        dec_msg <bytes> - decrypted message
    """
    if isinstance(enc_msg, str):
        enc_msg = enc_msg.encode(encoding)
    dec_msg = cipher.decrypt(
        enc_msg,
        asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(),
                      label=None))
    return dec_msg


def session_keys(fernet_key=True, block_size=8):
    """
    Create a session key and hash from a number of random bits

    Args:
        None

    Kwargs:
        block_size <int> - number of bytes

    Return:
        rand, hash <bytes> - sequence of random bits and corresponding hash

    Note:
        if AES encryption cipher is used, block_size should be N16
    """
    if fernet_key:
        rand8 = Fernet.generate_key()
    else:
        rand8 = base64.b64encode(os.urandom(block_size))
    hash8 = get_hash(rand8)
    return rand8, hash8


def get_hash(key, encoding=fc.DEFAULT_ENC):
    """
    Calculate SHA256 hash of a given key

    Args:
        key <bytes> - a (public) key

    Kwargs:
        encoding <str> - string coding

    Return:
        hash_key <bytes> - corresponding hash
    """
    if isinstance(key, str):
        key = key.encode(encoding)
    hash_key = hashlib.sha256(key).hexdigest().encode(encoding)
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
    hash_pub = hashlib.sha256(key).hexdigest().encode(encoding)
    return hash_pub == hash_key


def block_pad(msg, block_size=128, encoding=fc.DEFAULT_ENC):
    """
    Wrapper for padding a unencoded message

    Args:
        msg <str> - unpadded message

    Kwargs:
        block_size <int> - default: N16; for AES encryption cipher
        encoding <str> - string coding

    Return:
        msg_pad <bytes> - padded message of size N blocks
    """
    if isinstance(msg, str):
        msg = msg.encode(encoding)
    padder = sym_pad.PKCS7(block_size).padder()
    pad_msg = padder.update(msg)
    pad_msg += padder.finalize()
    return pad_msg


def block_unpad(msg, block_size=128, encoding=fc.DEFAULT_ENC):
    """
    Wrapper for unpadding a decoded message

    Args:
        msg <str/bytes> - padded message

    Kwargs:
        block_size <int> - default: N16; for AES encryption cipher
        encoding <str> - string coding

    Return:
        msg_unpad <str> - unpadded message
    """
    unpadder = sym_pad.PKCS7(block_size).unpadder()
    msg_unpad = unpadder.update(msg)
    msg_unpad = msg_unpad + unpadder.finalize()
    if isinstance(msg_unpad, bytes):
        msg_unpad = msg_unpad.decode(encoding)
    return msg_unpad


def AES_from_key(key, iv=None, iv_block=16, encoding=fc.DEFAULT_ENC):
    """
    Create an AES cipher from a key

    Args:
        key <bytes> - session key of size 8 or 16

    Kwargs:
        iv <bytes> - initialization vector
        iv_block <int> - size of the random initialization vector for CBC mode
        encoding <str> - string coding

    Return:
        cipher <cryptography..Cipher object> - AES cipher
    """
    if isinstance(key, str):
        key = key.encode(encoding)
    if len(key) == 8:
        key2 = key + key[::-1]
    elif len(key) == 16:
        key2 = key
    elif len(key) > 16:
        key2 = key[:16]
    else:
        fab_log('AES requires a cipher key of length of N16!', verbose_mode=5)
        return
    iv = iv if iv is not None else key2
    AES_cipher = ciphers.Cipher(
        algorithm=ciphers.algorithms.AES(key2),
        mode=ciphers.modes.CBC(iv))
    return AES_cipher


def AES_encrypt(message, key, **kwargs):
    """
    Encrypt a message using AES cipher

    Args:
        message <str> - message to be encrypted
        key <bytes> - session key of size 8 or 16

    Kwargs:
        iv <bytes> - initialization vector
        iv_block <int> - size of the random initialization vector for CBC mode
        encoding <str> - string coding

    Return:
        msg_enc <bytes> - encrypted message
    """
    if not message:
        return message
    message = block_pad(message)
    if key is None:
        fab_log('Encryption requires a cipher key!', verbose_mode=4)
        return
    cipher = AES_from_key(key, **kwargs)
    encoder = cipher.encryptor()
    msg_enc = encoder.update(message) + encoder.finalize()
    return msg_enc


def AES_decrypt(message, key, **kwargs):
    """
    Decrypt a message using AES cipher

    Args:
        message <bytes> - message to be decrypted
        key <bytes> - session key of size 8 or 16

    Kwargs:
        iv <bytes> - initialization vector
        iv_block <int> - size of the random initialization vector for CBC mode
        encoding <str> - string coding

    Return:
        msg_dec <bytes> - decrypted message
    """
    if not message:
        return message
    if key is None:
        fab_log('Decryption requires a cipher key!', verbose_mode=4)
        return
    cipher = AES_from_key(key, **kwargs)
    dec_cipher = cipher.decryptor()
    msg_dec = dec_cipher.update(message) + dec_cipher.finalize()
    msg_dec = block_unpad(msg_dec)
    return msg_dec


def Fernet_from_key(key, encoding=fc.DEFAULT_ENC):
    """
    Create a Fernet cipher from a key

    Args:
        key <bytes> - session key of size 8 or 16

    Kwargs:
        encoding <str> - string coding

    Return:
        cipher <cryptography.fernet.Fernet object> - Fernet cipher
    """
    if isinstance(key, str):
        key = key.encode(encoding)
    return Fernet(key)


def Fernet_encrypt(message, key, encoding=fc.DEFAULT_ENC):
    """
    Fernet encryption scheme

    Args:
        message <bytes> - message to be encrypted
        key <bytes> - Fernet session key

    Kwargs:
        encoding <str> - string coding

    Return:
        msg_enc <bytes> - encrypted message
    """
    if not message or key is None:
        return message
    if isinstance(message, str):
        message = message.encode(encoding)
    f = Fernet_from_key(key)
    return f.encrypt(message)


def Fernet_decrypt(message, key, encoding=fc.DEFAULT_ENC):
    """
    Fernet decryption scheme

    Args:
        message <bytes> - message to be decrypted
        key <bytes> - Fernet session key

    Kwargs:
        encoding <str> - string coding

    Return:
        msg_dec <bytes> - decrypted message
    """
    if not message or key is None:
        return message
    if isinstance(message, str):
        message = message.encode(encoding)
    f = Fernet_from_key(key)
    return f.decrypt(message)


class Secrets(object):
    """
    Data structure to facilitate encryption handshake
    """
    def __init__(self, private=None,
                 public=None, public_hash=None,
                 session=None, session_hash=None):
        self.public = public
        self.public_hash = public_hash
        self.private = private
        self.session = session
        self.session_hash = session_hash
        self.pw = None

    @classmethod
    def random(cls, **kwargs):
        """
        Instantiate all secret keys randomly

        Args:
            None

        Kwargs:
            size <int> - byte size of the key
            password <bytes> - optional password
            file_id <str> - file prefix, e.g. user-id
            file_dir <str> - target directory; [default: .fabular/rsa/]

        Return:
            secrets <Secrets object>
        """
        pub, priv = generate_RSAk(**kwargs)
        hashpub = get_hash(pub)
        key8, hash8 = session_keys(fernet_key=True)
        instance = cls(priv, pub, hashpub, key8, hash8)
        if 'password' in kwargs:
            instance.pw = kwargs['password']
        return instance

    @classmethod
    def from_RSA_fileID(cls, file_id, **kwargs):
        """
        Load RSA secrets from file_id

        Args:
            file_id <str> - file prefix, e.g. user-id

        Kwargs:
            size <int> - byte size of the key
            file_dir <str> - target directory; [default: .fabular/rsa/]

        Return:
            secrets <Secrets object>
        """
        pub, priv = generate_RSAk(file_id=file_id, **kwargs)
        hashpub = get_hash(pub)
        return cls(priv, pub, hashpub)

    @classmethod
    def from_keys(cls, keys, encoding=fc.DEFAULT_ENC):
        """
        Load secrets from a concatenated byte-string of keys
        b'<public>:::<public_hash>:::<session>:::<session_hash>'

        Args:
            keys <bytes> - concatenated byte-string

        Kwargs:
            None

        Return:
            secrets <Secrets object>
        """
        if isinstance(keys, str):
            keys = keys.encode(encoding)
        pub, hash_key, sess_key, sess_hash = keys.split(CCSEQ)
        if check_hash(pub, hash_key) and check_hash(sess_key, sess_hash):
            return cls(public=pub, public_hash=hash_key,
                       session=sess_key, session_hash=sess_hash)
        else:
            return None

    @classmethod
    def from_pubkey(cls, pubkey, encoding=fc.DEFAULT_ENC):
        """
        Load secrets from a concatenated byte-string of public key + hash
        b'<public>:::<public_hash>'

        Args:
            pubkey <bytes> - concatenated byte-string

        Kwargs:
            None

        Return:
            secrets <Secrets object>
        """
        if isinstance(pubkey, str):
            pubkey = pubkey.encode(encoding)
        pub, hash_key = pubkey.split(CCSEQ)
        if check_hash(pub, hash_key):
            return cls(public=pub, public_hash=hash_key)
        else:
            return None

    @classmethod
    def from_sesskey(cls, session, encoding=fc.DEFAULT_ENC):
        """
        Load secrets from a concatenated byte-string of session key + hash
        b'<session>:::<session_hash>'

        Args:
            keys <bytes> - concatenated byte-string

        Kwargs:
            None

        Return:
            secrets <Secrets object>
        """
        if isinstance(session, str):
            session = session.encode(encoding)
        sess_key, sess_hash = session.split(CCSEQ)
        if check_hash(sess_key, sess_hash):
            return cls(session=sess_key, session_hash=sess_hash)
        else:
            return None

    @property
    def keys(self):
        if self.public is not None and self.public_hash is not None\
           and self.session is not None and self.session_hash is not None:
            return CCSEQ.join([self.public, self.public_hash, self.session, self.session_hash])
        return None

    @keys.setter
    def keys(self, keys):
        self.public, self.public_hash, self.session, self.session_hash = \
            keys.split(CCSEQ)

    @property
    def pubkey(self):
        if self.public is not None and self.public_hash is not None:
            return CCSEQ.join([self.public, self.public_hash])
        return None

    @pubkey.setter
    def pubkey(self, pubkey):
        self.public, self.public_hash = pubkey.split(CCSEQ)

    @property
    def sesskey(self):
        if self.session is not None and self.session_hash is not None:
            return CCSEQ.join([self.session, self.session_hash])
        return None

    @sesskey.setter
    def sesskey(self, sesskey):
        self.session, self.session_hash = sesskey.split(CCSEQ)

    def check_hash(self):
        """
        Check hashes for public and/or session key

        Args/Kwargs:
            None

        Return:
            hash_check <bool> - comparison of hashes to their keys
        """
        hash_check = False
        if self.public and self.public_hash:
            hash_check = check_hash(self.public, self.public_hash)
        if self.session and self.session_hash:
            hash_check = check_hash(self.session, self.session_hash)
        return hash_check

    @property
    def key128(self):
        """
        A 128-bit key based on the (random) session key
        """
        if self.session and len(self.session) == 8:
            return self.session + self.session[::-1]
        elif self.session and len(self.session) == 16:
            return self.session
        elif self.session and len(self.session) > 16:
            return self.session[:16]
        else:
            rand16 = os.urandom(16)
            self.session = rand16
            self.session_hash = get_hash(rand16)
            return rand16

    @property
    def RSA(self):
        """
        RSA cipher object table from public and/or private keys
        """
        rsa = {}
        if self.private:
            rsa['private'] = RSA_from_key(self.private, self.pw)
            rsa['priv'] = rsa['private']
        if self.public:
            rsa['public'] = RSA_from_key(self.public)
            rsa['pub'] = rsa['public']
        return rsa

    def RSA_encrypt(self, data, encoding=fc.DEFAULT_ENC):
        """
        Use a (public) RSA cipher to encrypt a message

        Args:
            data <bytes> - message to be encrypted

        Kwargs:
            encoding <str> - string coding

        Return:
            enc_msg <bytes> - encrypted message
        """
        enc_msg = RSA_encrypt(data, self.RSA['public'], encoding=encoding)
        return enc_msg

    def RSA_decrypt(self, data, encoding=fc.DEFAULT_ENC):
        """
        Use a (private) RSA cipher to decrypt a message

        Args:
            data <bytes> - message to be decrypted

        Kwargs:
            encoding <str> - string coding

        Return:
            dec_msg <bytes> - decrypted message        
        """
        dec_msg = RSA_decrypt(data, self.RSA['private'], encoding=encoding)
        return dec_msg

    def AES_encrypt(self, message, key=None, **kwargs):
        """
        Fast AES encryption of a message

        Args:
            message <bytes> - message to be encrypted

        Kwargs:
            key <bytes> - session key of size 8 or 16
            iv <bytes> - initialization vector
            iv_block <int> - size of the random initialization vector for CBC mode
            encoding <str> - string coding

        Return:
            msg_enc <bytes> - encrypted message
        """
        if not message:
            return message
        key = self.key128 if key is None else key
        if self.key128 is None:
            fab_log('Encryption failed! Proceeding without encryption...',
                    verbose_mode=4)
            return message
        msg_enc = AES_encrypt(message, key, **kwargs)
        return msg_enc

    def AES_decrypt(self, message, key=None, **kwargs):
        """
        Fast AES decryption of a message

        Args:
            message <bytes> - message to be decrypted

        Kwargs:
            key <bytes> - session key of size 8 or 16
            iv <bytes> - initialization vector
            iv_block <int> - size of the random initialization vector for CBC mode
            encoding <str> - string coding

        Return:
            msg_dec <str> - decrypted message
        """
        if not message:
            return message
        key = self.key128 if key is None else key
        if self.key128 is None:
            fab_log('Decryption requires a cipher key!', verbose_mode=4)
            return message
        msg_dec = AES_decrypt(message, key, **kwargs)
        return msg_dec

    def Fernet_encrypt(self, message, key=None, **kwargs):
        """
        Fernet encryption scheme

        Args:
            message <bytes> - message to be encrypted

        Kwargs:
            key <bytes> - Fernet session key
            encoding <str> - string coding

        Return:
            msg_enc <bytes> - encrypted message
        """
        if not message:
            return message
        key = self.session if key is None else key
        if self.session is None:
            fab_log('Encryption failed! Proceeding without encryption...',
                    verbose_mode=4)
            return message
        msg_enc = Fernet_encrypt(message, key, **kwargs)
        return msg_enc

    def Fernet_decrypt(self, message, key=None, **kwargs):
        """
        Fernet decryption scheme

        Args:
            message <bytes> - message to be decrypted

        Kwargs:
            key <bytes> - Fernet session key
            encoding <str> - string coding

        Return:
            msg_dec <bytes> - decrypted message
        """
        if not message:
            return message
        key = self.session if key is None else key
        if self.session is None:
            fab_log('Encryption failed! Proceeding without encryption...',
                    verbose_mode=4)
            return message
        msg_dec = Fernet_decrypt(message, key, **kwargs)
        return msg_dec

    def hybrid_encrypt(self, data, iv=None, encoding=fc.DEFAULT_ENC):
        """
        Hybrid encryption of a message using RSA and AES ciphers

        Args:
            data <str> - message to be encrypted

        Kwargs:
            iv <bytes> - initialization vector
            encoding <str> - string coding

        Return:
            enc_msg <bytes> - encrypted message
        """
        if isinstance(data, str):
            data = data.encode(encoding)
        iv = iv if iv is not None else os.urandom(16)
        keyiv = CCSEQ.join([self.key128, iv])
        rsa_enckey = self.RSA_encrypt(keyiv)
        aes_ciphertext = self.AES_encrypt(data, key=self.key128, iv=iv)
        return CCSEQ.join([rsa_enckey, aes_ciphertext])

    def hybrid_decrypt(self, encrypted_data, encoding=fc.DEFAULT_ENC):
        """
        Hybrid decryption of an encoded message using RSA and AES ciphers

        Args:
            data <str> - message to be decrypted

        Kwargs:
            iv <bytes> - initialization vector
            encoding <str> - string coding

        Return:
            dec_msg <bytes> - decrypted message
        """
        if self.private is None:
            return b''
        if isinstance(encrypted_data, (tuple, list)):
            rsa_enckey, aes_ciphertext = encrypted_data
        elif isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode(encoding)
            rsa_enckey, aes_ciphertext = encrypted_data.split(CCSEQ)
        else:
            rsa_enckey, aes_ciphertext = encrypted_data.split(CCSEQ)
        key = self.RSA_decrypt(rsa_enckey)
        session, iv = key.split(CCSEQ)
        data = self.AES_decrypt(aes_ciphertext, key=session, iv=iv)
        return data


if __name__ == "__main__":

    from tests.prototype import SequentialTestLoader
    from tests.crypt_test import CryptModuleTest
    loader = SequentialTestLoader()
    loader.proto_load(CryptModuleTest)
    loader.run_suites()
