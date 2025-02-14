"""
fabular - tests.crypt_test

@author: phdenzel
"""
import sys
import os
import base64
import fabular.crypt as fcrypt
from unittest import mock
from tests.prototype import UnitTestPrototype
from tests.prototype import SequentialTestLoader


class CryptModuleTest(UnitTestPrototype):

    def setUp(self):
        # arguments and keywords
        print("")
        print(self.separator)
        print(self.shortDescription())

    def tearDown(self):
        print("")

    @mock.patch("getpass.getpass")
    def test_pw_prompt_confirm(self, password):
        """ # fabular.crypt.pw_prompt(confirm=True) """
        self.printf(dict(confirm=True))
        with self.assertRaises(OSError) as context:
            password.side_effect = OSError("Passwords don't match!")
            fcrypt.pw_prompt(confirm=True)
            self.assertTrue("Passwords don't match!" in context.exception)

    @mock.patch("getpass.getpass")
    def test_pw_prompt_once(self, password):
        """ # fabular.crypt.pw_prompt(confirm=False) """
        self.printf(dict(confirm=False))
        password.return_value = "Some phrase"
        pw = fcrypt.pw_prompt(confirm=False)
        self.printout(pw)

    def test_generate_RSAk(self):
        """ # fabular.crypt.generate_RSAk """
        kw = dict(file_dir=None, size=1024)
        self.printf(kw)
        pub, priv = fcrypt.generate_RSAk(**kw)
        self.assertTrue(pub)
        self.assertTrue(priv)
        self.assertIsInstance(pub, bytes)
        self.assertIsInstance(priv, bytes)
        pubk, privk = pub.split(b'\n')[1], priv.split(b'\n')[1]
        self.assertEqual(len(pubk+privk), kw['size']//8)
        self.printout((pub, priv))

        kw = dict(file_id='test', file_dir='.testing/rsa', size=1024)
        self.printf(kw)
        pub, priv = fcrypt.generate_RSAk(**kw)
        self.assertTrue(pub)
        self.assertTrue(priv)
        self.assertIsInstance(pub, bytes)
        self.assertIsInstance(priv, bytes)
        files = [os.path.join(kw['file_dir'], kw['file_id']+'_rsa'),
                 os.path.join(kw['file_dir'], kw['file_id']+'_rsa.pub')]
        self.assertTrue(os.path.exists(files[0]))
        self.assertTrue(os.path.exists(files[1]))
        pubk, privk = pub.split(b'\n')[1], priv.split(b'\n')[1]
        self.assertEqual(len(pubk+privk), kw['size']//8)
        os.remove(files[0])
        os.remove(files[1])
        os.rmdir(kw['file_dir'])
        os.rmdir(os.path.dirname(kw['file_dir']))
        self.printout((pub, priv))

    def test_RSA_from_key(self):
        """ # fabular.crypt.RSA_from_key """
        pub, priv = fcrypt.generate_RSAk(file_id='server', password=None)

        self.printf(pub)
        rsapubk = fcrypt.RSA_from_key(pub)
        self.assertIsInstance(rsapubk, object)
        self.printout(rsapubk)

        self.printf(priv)
        rsaprivk = fcrypt.RSA_from_key(priv)
        self.assertIsInstance(rsaprivk, object)
        self.printout(rsaprivk)

    def test_RSA_encrypt(self):
        """ # fabular.crypt.RSA_encrypt """
        message = b'Eureka! Encrypt+Decrypt success!'
        pub, priv = fcrypt.generate_RSAk(file_id='server', password=None)
        self.printf((message, pub))
        enc_msg = fcrypt.RSA_encrypt(message, fcrypt.RSA_from_key(pub))
        self.assertNotEqual(message, enc_msg)
        self.printout(enc_msg)

    def test_RSA_decrypt(self):
        """ # fabular.crypt.RSA_decrypt """
        message = b'Eureka! Encrypt+Decrypt success!'
        pub, priv = fcrypt.generate_RSAk(file_id='server', password=None)
        enc_msg = fcrypt.RSA_encrypt(message, fcrypt.RSA_from_key(pub))
        self.printf((enc_msg, priv))
        dec_msg = fcrypt.RSA_decrypt(enc_msg, fcrypt.RSA_from_key(priv))
        self.assertEqual(message, dec_msg)
        self.printout(dec_msg)

    def test_session_keys(self):
        """ # fabular.crypt.session_keys """
        kw = dict(fernet_key=False, block_size=8)
        self.printf(kw)
        k, h = fcrypt.session_keys(**kw)
        self.assertTrue(k)
        self.assertTrue(h)
        self.assertIsInstance(k, bytes)
        self.assertIsInstance(h, bytes)
        self.assertEqual(len(k), 4*kw['block_size']//3 + 2)
        self.printout((k, h))

        kw = dict(fernet_key=False, block_size=32)
        self.printf(kw)
        k, h = fcrypt.session_keys(**kw)
        self.assertTrue(k)
        self.assertTrue(h)
        self.assertIsInstance(k, bytes)
        self.assertIsInstance(h, bytes)
        self.assertEqual(len(k), 4*kw['block_size']//3 + 2)
        self.printout((k, h))

        kw = dict(fernet_key=True)
        self.printf(kw)
        k, h = fcrypt.session_keys(**kw)
        self.assertTrue(k)
        self.assertTrue(h)
        self.assertIsInstance(k, bytes)
        self.assertIsInstance(h, bytes)
        # self.assertNotEqual()
        self.printout((k, h))

    def test_get_hash(self):
        """ # fabular.crypt.get_hash """
        randb = b'12345678'
        self.printf(randb)
        h = fcrypt.get_hash(randb)
        self.assertEqual(len(h)*8, 512)
        self.printout(h)

        randb = '1234'
        self.printf(randb)
        h = fcrypt.get_hash(randb)
        self.assertEqual(len(h)*8, 512)
        self.printout(h)

    def test_check_hash(self):
        """ # fabular.crypt.check_hash """
        k = b''
        h = b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        self.printf((k, h))
        check = fcrypt.check_hash(k, h)
        self.assertTrue(check)
        self.printout(check)

        k = b'a'
        h = b'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
        self.printf((k, h))
        check = fcrypt.check_hash(k, h)
        self.assertTrue(check)
        self.printout(check)

    def test_block_pad(self):
        """ # fabular.crypt.block_pad """
        padded_test = b'a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
        unpadd = 'a'
        self.printf(unpadd)
        padded = fcrypt.block_pad(unpadd)
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(len(padded), len(padded_test))
        self.assertEqual(padded, padded_test)
        self.printout(padded)

        padded_test = (
            b'abcdefghijklmnop\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
            b'\x10\x10\x10\x10')
        unpadd = 'abcdefghijklmnop'
        self.printf(unpadd)
        padded = fcrypt.block_pad(unpadd)
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(len(padded), len(padded_test))
        self.assertEqual(padded, padded_test)
        self.printout(padded)

        padded_test = b'abcdefghijklmno\x01'
        unpadd = 'abcdefghijklmno'
        self.printf(unpadd)
        padded = fcrypt.block_pad(unpadd)
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(len(padded), len(padded_test))
        self.assertEqual(padded, padded_test)
        self.printout(padded)

    def test_block_unpad(self):
        """ # fabular.crypt.block_unpad """
        unpadd_test = 'a'
        padded = b'a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
        self.printf(padded)
        self.assertEqual(len(padded) % 16, 0)
        unpadd = fcrypt.block_unpad(padded)
        self.assertEqual(len(unpadd), len(unpadd_test))
        self.assertEqual(unpadd, unpadd_test)
        self.printout(unpadd)

        unpadd_test = 'abcdefghijklmnop'
        padded = (
            b'abcdefghijklmnop\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
            b'\x10\x10\x10\x10')
        self.printf(padded)
        self.assertEqual(len(padded) % 16, 0)
        unpadd = fcrypt.block_unpad(padded)
        self.assertEqual(len(unpadd), len(unpadd_test))
        self.assertEqual(unpadd, unpadd_test)
        self.printout(unpadd)

        unpadd_test = 'abcdefghijklmno'
        padded = b'abcdefghijklmno\x01'
        self.printf(padded)
        self.assertEqual(len(padded) % 16, 0)
        unpadd = fcrypt.block_unpad(padded)
        self.assertEqual(len(unpadd), len(unpadd_test))
        self.assertEqual(unpadd, unpadd_test)
        self.printout(unpadd)

    def test_AES_from_key(self):
        """ # fabular.crypt.AES_from_key """
        k = b'123456'
        self.printf(k)
        cipher = fcrypt.AES_from_key(k)
        self.assertIsNone(cipher)
        self.printout(cipher)

        k = b'12345678'
        self.printf(k)
        cipher = fcrypt.AES_from_key(k)
        self.assertIsNotNone(cipher)
        self.printout(cipher)

        k = '12345678'*2
        self.printf(k)
        cipher = fcrypt.AES_from_key(k)
        self.assertIsNotNone(cipher)
        self.printout(cipher)

        k = b'12345678'*4
        self.printf(k)
        cipher = fcrypt.AES_from_key(k)
        self.assertIsNotNone(cipher)
        self.printout(cipher)

    def test_AES_encrypt(self):
        """ # fabular.crypt.AES_encrypt """
        test_msg = "Eureka! Encrypt+Decrypt success!"
        k = b'\xbdhe<\x87\x967\xcf'
        result = (
            b'\x9f\xab\xf0K\x1ad\xf5O?\xaf\xbe\xdc3\n\xd9?KX\x0f\x12#{\x9d\x06'
            b'\xd65\x9e~\xd9\x1e\xa2<\xdc\x82U\xfe\xf8\x13_\x99|\xdeI\xb9\x9f'
            b'\xb4>\x8c')
        self.printf((test_msg, {'key': k}))
        msg_enc = fcrypt.AES_encrypt(test_msg, key=k)
        self.assertIsInstance(msg_enc, bytes)
        self.assertEqual(msg_enc, result)
        self.printout(msg_enc)

        self.printf((test_msg, {'key': None}))
        msg = fcrypt.AES_encrypt(test_msg, key=None)
        self.assertIsNone(msg)
        self.printout(msg)

        self.printf(('', {'key': k}))
        msg = fcrypt.AES_encrypt('', key=k)
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_AES_decrypt(self):
        """ # fabular.crypt.AES_decrypt """
        msg_enc = (
            b'\x9f\xab\xf0K\x1ad\xf5O?\xaf\xbe\xdc3\n\xd9?KX\x0f\x12#{\x9d\x06'
            b'\xd65\x9e~\xd9\x1e\xa2<\xdc\x82U\xfe\xf8\x13_\x99|\xdeI\xb9\x9f'
            b'\xb4>\x8c')
        k = b'\xbdhe<\x87\x967\xcf'
        test_msg = "Eureka! Encrypt+Decrypt success!"
        self.printf((msg_enc, {'key': k}))
        msg_dec = fcrypt.AES_decrypt(msg_enc, key=k)
        self.assertIsInstance(msg_dec, str)
        self.assertEqual(msg_dec, test_msg)
        self.printout(msg_dec)

        self.printf((msg_enc, {'key': None}))
        msg = fcrypt.AES_decrypt(msg_enc, key=None)
        self.assertIsNone(msg)
        self.printout(msg)

        self.printf(('', {'key': k}))
        msg = fcrypt.AES_decrypt('', key=k)
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_Fernet_from_key(self):
        """ # fabular.crypt.Fernet_from_key """
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        self.printf(k)
        cipher = fcrypt.Fernet_from_key(k)
        self.assertIsNotNone(cipher)
        self.printout(cipher)

        k, _ = fcrypt.session_keys(fernet_key=False, block_size=32)
        self.printf(k)
        cipher = fcrypt.Fernet_from_key(k)
        self.assertIsNotNone(cipher)
        self.printout(cipher)

        k, _ = fcrypt.session_keys(fernet_key=False, block_size=48)
        self.printf(k)
        with self.assertRaises(ValueError) as context:
            fcrypt.Fernet_from_key(k)
            self.assertTrue("base64" in context.exception)

    def test_Fernet_encrypt(self):
        """ # fabular.crypt.Fernet_encrypt """
        test_msg = "Eureka! Encrypt+Decrypt success!"
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        self.printf((test_msg, {'key': k}))
        msg_enc = fcrypt.Fernet_encrypt(test_msg, key=k)
        self.assertIsInstance(msg_enc, bytes)
        self.assertIsNotNone(msg_enc)
        self.assertNotEqual(msg_enc, test_msg)
        self.printout(msg_enc)

        self.printf((test_msg, {'key': None}))
        msg = fcrypt.Fernet_encrypt(test_msg, key=None)
        self.assertEqual(msg, test_msg)
        self.printout(msg)

        self.printf(('', {'key': k}))
        msg = fcrypt.AES_encrypt('', key=k)
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_Fernet_decrypt(self):
        """ # fabular.crypt.Fernet_decrypt """
        msg_enc = (
            b'gAAAAABgSKNfvwqUVAQQPvrhSMpGMRV1XKuJxvcmvrnLezEjyGIPZX16NtJZexA-CEtSzhw9vYiC'
            b'TDHwS7t7G0j8VW--QnF4Qf85pseqz5UVTHME0_IY4r0ZeCAcnQpxhyIWbucZEAXT')
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        test_msg = b"Eureka! Encrypt+Decrypt success!"
        self.printf((msg_enc, {'key': k}))
        msg_dec = fcrypt.Fernet_decrypt(msg_enc, key=k)
        self.assertIsInstance(msg_dec, bytes)
        self.assertEqual(msg_dec, test_msg)
        self.printout(msg_dec)

        self.printf((msg_enc, {'key': None}))
        msg = fcrypt.Fernet_decrypt(msg_enc, key=None)
        self.assertEqual(msg, msg_enc)
        self.printout(msg)

        self.printf(('', {'key': k}))
        msg = fcrypt.Fernet_decrypt('', key=k)
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_Secrets(self):
        """ # fabular.crypt.Secrets """
        kw = dict(size=1024)
        self.printf(kw)
        secret = fcrypt.Secrets.random(**kw)
        self.assertIsInstance(secret, fcrypt.Secrets)
        self.assertTrue(hasattr(secret, 'public'))
        self.assertTrue(hasattr(secret, 'private'))
        self.assertTrue(hasattr(secret, 'session'))
        self.assertTrue(secret.check_hash())
        pubk = secret.public.split(b'\n')[1]
        prvk = secret.private.split(b'\n')[1]
        self.assertEqual(8*(len(pubk)+len(prvk)), kw['size'])
        self.assertIsInstance(secret.RSA, dict)
        self.assertIsNone(secret.pw)
        self.printout(secret)

    def test_Secrets_from_pubkey(self):
        """ # fabular.crypt.Secrets.from_pubkey """
        pubkey = (b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADC'
                  b'BiQKBgQCuz76KzzPu8jjiannA4Ocb9Q8v\nr/0j+buHqaF43wkOBNlUywjX'
                  b'oFxZhIAUQQj/HjgKd2GebkHKEijQnl+b0jzUYmy9\nQ1yQcghhip9fKcP6o'
                  b'FLchNyzm1+Y5PXoSMxgGLhmdH/KsbOozyOvlCKaRKdalkpk\neeZkVS6SAY'
                  b'425TWLzQIDAQAB\n-----END PUBLIC KEY-----:::c8e2d0c4fd609521'
                  b'5b5fb64048622d26d576f855adc1f28faa9b3f6ae0fce903')
        self.printf(pubkey)
        secret = fcrypt.Secrets.from_pubkey(pubkey)
        self.assertIsInstance(secret, fcrypt.Secrets)
        self.assertTrue(hasattr(secret, 'public'))
        self.assertTrue(hasattr(secret, 'private'))
        self.assertTrue(hasattr(secret, 'session'))
        self.assertIsNotNone(secret.public)
        self.assertIsNotNone(secret.public_hash)
        self.assertIsNone(secret.private)
        self.assertIsNone(secret.session)
        self.assertIsNone(secret.session_hash)
        self.assertIsNone(secret.pw)
        self.assertTrue(secret.check_hash())
        self.printout(secret)

    def test_Secrets_from_sesskey(self):
        """ # fabular.crypt.Secrets.from_sesskey """
        sesskey = (b'\x88\xe1A\xf8A\xab\xb0\xd1:::aef046b920c3bfdd45db12dca7726'
                   b'1128e3ab4a14c33133a072b6b01a29c3b65')
        self.printf(sesskey)
        secret = fcrypt.Secrets.from_sesskey(sesskey)
        self.assertIsInstance(secret, fcrypt.Secrets)
        self.assertTrue(hasattr(secret, 'public'))
        self.assertTrue(hasattr(secret, 'private'))
        self.assertTrue(hasattr(secret, 'session'))
        self.assertIsNone(secret.public)
        self.assertIsNone(secret.public_hash)
        self.assertIsNone(secret.private)
        self.assertIsNotNone(secret.session)
        self.assertIsNotNone(secret.session_hash)
        self.assertIsNone(secret.pw)
        self.assertTrue(secret.check_hash())
        self.printout(secret)

    def test_Secrets_from_keys(self):
        """ # fabular.crypt.Secrets.from_keys """
        keys = (b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBi'
                b'QKBgQCuz76KzzPu8jjiannA4Ocb9Q8v\nr/0j+buHqaF43wkOBNlUywjXoFxZ'
                b'hIAUQQj/HjgKd2GebkHKEijQnl+b0jzUYmy9\nQ1yQcghhip9fKcP6oFLchNy'
                b'zm1+Y5PXoSMxgGLhmdH/KsbOozyOvlCKaRKdalkpk\neeZkVS6SAY425TWLzQ'
                b'IDAQAB\n-----END PUBLIC KEY-----:::c8e2d0c4fd6095215b5fb64048'
                b'622d26d576f855adc1f28faa9b3f6ae0fce903:::\x84\x99e*\x83\xec}'
                b'\x9e:::4c3fa69b92e89b59a3c8929e93e07417631cc992afd63d5ad303ee'
                b'bb5e0a3f75')
        self.printf(keys)
        secret = fcrypt.Secrets.from_keys(keys)
        self.assertIsInstance(secret, fcrypt.Secrets)
        self.assertTrue(hasattr(secret, 'public'))
        self.assertTrue(hasattr(secret, 'private'))
        self.assertTrue(hasattr(secret, 'session'))
        self.assertIsNotNone(secret.public)
        self.assertIsNotNone(secret.public_hash)
        self.assertIsNone(secret.private)
        self.assertIsNotNone(secret.session)
        self.assertIsNotNone(secret.session_hash)
        self.assertIsNone(secret.pw)
        self.assertTrue(secret.check_hash())
        self.printout(secret)

    def test_Secrets_RSA_encrypt(self):
        """ # fabular.crypt.Secrets.RSA_encrypt """
        message = b'Eureka! Encrypt+Decrypt success!'
        secrets = fcrypt.Secrets.from_RSA_fileID(file_id='server', password=None)
        self.printf(message)
        enc_msg = secrets.RSA_encrypt(message)
        self.assertNotEqual(message, enc_msg)
        self.printout(enc_msg)

    def test_Secrets_RSA_decrypt(self):
        """ # fabular.crypt.Secrets.RSA_decrypt """
        message = b'Eureka! Encrypt+Decrypt success!'
        secrets = fcrypt.Secrets.from_RSA_fileID(file_id='server', password=None)
        enc_msg = secrets.RSA_encrypt(message)
        self.printf((enc_msg))
        dec_msg = secrets.RSA_decrypt(enc_msg)
        self.assertEqual(message, dec_msg)
        self.printout(dec_msg)

    def test_Secrets_AES_encrypt(self):
        """ # fabular.crypt.Secrets.AES_encrypt """
        kw = dict(size=1024)
        secret = fcrypt.Secrets.random(**kw)
        secret.sesskey = (b'5\x80\xffu\xe7\xad\xb4K:::'
                          b'bb3c4162c306318b5053232b161ff376'
                          b'691c63ed560f66043c34aee14dc88a21')
        msg = ("I've wrestled with an alligator, I done tussle with a whale, "
               "I done handcuffed lightnin' and thrown thunder in jail."
               "Only last week I murdered a rock, injured a stone, "
               "hospitalized a brick. I'm so mean, I make medicine sick.")
        test_msg = (b'\xb8_\x80\x03\xe5\x15_\xb8\xe0"\x84\xddb\xe4U\xe9\xdbe,'
                    b'\x96kN\xe8E} W\x80\xb7d\x8c\xe9\xff\x8fo\xbb3\r{\x0bE\xbb'
                    b'\x1b\xe0#\x17\xcf\xf5\xa7\t\xe2\xbaM\xffQrdG\xda\xe0\xb2'
                    b'\x92\xde1\x08\xae\xc8\xe2\xb8\xf0\xbe\x12+\x99\xd2\xcfU'
                    b'\xf6\xf7VDj\xce\xd5N\xb9\'\xdfY\xb5\xc3\xe4H=^!fY+\x93'
                    b'\xc0\x84B\x9d\x94\xd4\x17\xbfy\xb8QMY\x04\xa1\x04\x0chT'
                    b'\xa1?\x02J\xf8\xfd8\xdd%\x01\xcdT\x81R\x96\xe7\x12.\xb8'
                    b'\xf7\xac\x84\x9f\xc8\xac#\x01=\xe7\xa3Ov\xa3\x1e\xa0\x15'
                    b'\xc2!w\x9c\xed\xb1c\x93\x80\nt\xee\x9f\x19\x1aE\x96\xe8i'
                    b'\xe9`\x87\xfa\xf9$0\x9c\x85\xab\x15\xcd\xac\x08i\x8c\x0c'
                    b'\xd5V\xffT\x9aP\x00\x15\x87\xfa!X\x1a6.\xd4wn\xe9\xae'
                    b'\x01Z\x9a\x8a\xefUZ\x8ew-\xf9K\xca')
        self.printf(msg)
        msg_enc = secret.AES_encrypt(msg)
        self.assertEqual(msg_enc, test_msg)
        self.printout(msg_enc)

    def test_Secrets_AES_decrypt(self):
        """ # fabular.crypt.Secrets.AES_decrypt """

        kw = dict(size=1024)
        secret = fcrypt.Secrets.random(**kw)
        secret.sesskey = (b'5\x80\xffu\xe7\xad\xb4K:::'
                          b'bb3c4162c306318b5053232b161ff376'
                          b'691c63ed560f66043c34aee14dc88a21')
        msg_enc = (b'\xb8_\x80\x03\xe5\x15_\xb8\xe0"\x84\xddb\xe4U\xe9\xdbe,'
                   b'\x96kN\xe8E} W\x80\xb7d\x8c\xe9\xff\x8fo\xbb3\r{\x0bE\xbb'
                   b'\x1b\xe0#\x17\xcf\xf5\xa7\t\xe2\xbaM\xffQrdG\xda\xe0\xb2'
                   b'\x92\xde1\x08\xae\xc8\xe2\xb8\xf0\xbe\x12+\x99\xd2\xcfU'
                   b'\xf6\xf7VDj\xce\xd5N\xb9\'\xdfY\xb5\xc3\xe4H=^!fY+\x93'
                   b'\xc0\x84B\x9d\x94\xd4\x17\xbfy\xb8QMY\x04\xa1\x04\x0chT'
                   b'\xa1?\x02J\xf8\xfd8\xdd%\x01\xcdT\x81R\x96\xe7\x12.\xb8'
                   b'\xf7\xac\x84\x9f\xc8\xac#\x01=\xe7\xa3Ov\xa3\x1e\xa0\x15'
                   b'\xc2!w\x9c\xed\xb1c\x93\x80\nt\xee\x9f\x19\x1aE\x96\xe8i'
                   b'\xe9`\x87\xfa\xf9$0\x9c\x85\xab\x15\xcd\xac\x08i\x8c\x0c'
                   b'\xd5V\xffT\x9aP\x00\x15\x87\xfa!X\x1a6.\xd4wn\xe9\xae'
                   b'\x01Z\x9a\x8a\xefUZ\x8ew-\xf9K\xca')
        msg = ("I've wrestled with an alligator, I done tussle with a whale, "
               "I done handcuffed lightnin' and thrown thunder in jail."
               "Only last week I murdered a rock, injured a stone, "
               "hospitalized a brick. I'm so mean, I make medicine sick.")
        self.printf(msg_enc)
        msg_dec = secret.AES_decrypt(msg_enc)
        self.assertEqual(msg_dec, msg)
        self.printout(msg_dec)

    def test_Secrets_Fernet_encrypt(self):
        """ # fabular.crypt.Secrets.Fernet_encrypt """
        test_msg = "Eureka! Encrypt+Decrypt success!"
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf(test_msg)
        msg_enc = secrets.Fernet_encrypt(test_msg)
        self.assertIsInstance(msg_enc, bytes)
        self.assertIsNotNone(msg_enc)
        self.assertNotEqual(msg_enc, test_msg)
        self.printout(msg_enc)

        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf((test_msg, {'key': None}))
        msg = secrets.Fernet_encrypt(test_msg, key=None)
        self.assertIsInstance(msg, bytes)
        self.assertIsNotNone(msg)
        self.assertNotEqual(msg, test_msg)
        self.printout(msg)

        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf(('', {'key': b''}))
        msg = secrets.Fernet_encrypt('', key=b'')
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_Secrets_Fernet_decrypt(self):
        """ # fabular.crypt.Secrets.Fernet_decrypt """
        msg_enc = (
            b'gAAAAABgSKNfvwqUVAQQPvrhSMpGMRV1XKuJxvcmvrnLezEjyGIPZX16NtJZexA-CEtSzhw9vYiC'
            b'TDHwS7t7G0j8VW--QnF4Qf85pseqz5UVTHME0_IY4r0ZeCAcnQpxhyIWbucZEAXT')
        test_msg = b"Eureka! Encrypt+Decrypt success!"
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf((msg_enc))
        msg_dec = secrets.Fernet_decrypt(msg_enc)
        self.assertIsInstance(msg_dec, bytes)
        self.assertEqual(msg_dec, test_msg)
        self.printout(msg_dec)

        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf((msg_enc, {'key': None}))
        msg = secrets.Fernet_decrypt(msg_enc, key=None)
        self.assertEqual(msg, test_msg)
        self.printout(msg)

        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets(session=k)
        self.printf(('', {'key': b''}))
        msg = fcrypt.Fernet_decrypt('', key=b'')
        self.assertFalse(msg)
        self.assertIsInstance(msg, type(''))
        self.assertEqual(msg, '')
        self.printout(msg)

    def test_Secrets_hybrid_encrypt(self):
        """ # fabular.crypt.Secrets.hybrid_encrypt """
        test_msg = b"Eureka! Encrypt+Decrypt success!"
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets.from_RSA_fileID(file_id='server', password=None)
        secrets.session = k
        self.printf(test_msg)
        msg_enc = secrets.hybrid_encrypt(test_msg)
        self.assertIsInstance(msg_enc, bytes)
        self.assertIsNotNone(msg_enc)
        self.assertNotEqual(msg_enc, test_msg)
        self.printout(msg_enc)

    def test_Secrets_hybrid_decrypt(self):
        """ # fabular.crypt.Secrets.hybrid_decrypt """
        test_msg = b"Eureka! Encrypt+Decrypt success!"
        k = b'MUwV2jgqHXDsxcz-UWtyyy9tnTI5PUmh-eCRAWxPHf4='
        secrets = fcrypt.Secrets.from_RSA_fileID(file_id='server', password=None)
        secrets.session = k
        msg_enc = secrets.hybrid_encrypt(test_msg)
        self.printf((test_msg, msg_enc))
        msg_dec = secrets.hybrid_decrypt(msg_enc)
        self.assertIsInstance(msg_enc, bytes)
        self.assertIsNotNone(msg_dec)
        self.assertNotEqual(msg_dec, test_msg)
        self.printout(msg_dec)


if __name__ == "__main__":

    loader = SequentialTestLoader()
    loader.proto_load(CryptModuleTest)
    loader.run_suites()
