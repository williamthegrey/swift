from unittest import TestCase
from swift.encryption.utils.encryptionutils import AESCipher, RSACipher, CompositeCipher


class TestRSACipher(TestCase):
    def test_encrypt(self):
        pass

    def test_decrypt(self):
        pass

    def test_sign(self):
        pass

    def test_verify(self):
        pass

    def test_re_encrypt(self):
        pass


class TestAESCipher(TestCase):
    def test_new_key(self):
        pass

    def test_encrypt(self):
        pass

    def test_decrypt(self):
        pass

    def test_all(self):
        cipher = AESCipher()
        cipher.new_key()
        msg = "Nothing is true. Everything is permitted."
        msg_enc = cipher.encrypt(msg)
        msg_enc_dec = cipher.decrypt(msg_enc)
        self.assertEqual(msg, msg_enc_dec)


class TestCompositeCipher(TestCase):
    def setUp(self):
        user_id = 'william'
        self.local_key_path = '/etc/swift/encryption-server/' + user_id + '.pem'
        self.msg = "Nothing is true. Everything is permitted."

    def test_encrypt_sign(self):
        pass

    def test_verify_decrypt(self):
        pass

    def test_re_encrypt(self):
        pass

    def test_all(self):
        cipher = CompositeCipher(self.local_key_path)
        msg_dict = cipher.encrypt_sign(self.msg)
        msg_enc_dec = cipher.verify_decrypt(msg_dict['msg'], msg_dict['signature'], msg_dict['key'])

        self.assertEqual(self.msg, msg_enc_dec)
