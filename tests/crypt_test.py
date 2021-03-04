"""
fabular - tests.crypt_test

@author: phdenzel
"""
import fabular.crypt as fcrypt
import fabular.config as fc
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

    def test_generate_RSAk(self):
        """ # fabular.crypt.generate_RSAk """
        pass

    def test_session_keys(self):
        """ # fabular.crypt.session_keys """
        pass

    def test_get_hash(self):
        """ # fabular.crypt.get_hash """
        pass

    def test_check_hash(self):
        """ # fabular.crypt.check_hash """
        pass

    def test_block_pad(self):
        """ # fabular.crypt.block_pad """
        pass

    def test_block_unpad(self):
        """ # fabular.crypt.block_unpad """
        pass

    def test_AES_from_key(self):
        """ # fabular.crypt.AES_from_key """
        pass

    def test_encrypt_msg(self):
        """ # fabular.crypt.encrypt_msg """
        pass

    def test_decrypt_msg(self):
        """ # fabular.crypt.decrypt_msg """
        pass

    def test_Secrets(self):
        """ # fabular.crypt.Secrets """
        pass


if __name__ == "__main__":

    loader = SequentialTestLoader()
    loader.proto_load(CryptModuleTest)
    loader.run_suites()
