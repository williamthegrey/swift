from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS


class RSACipher(object):

    def __init__(self, local_key_path):
        self.local_key_path = local_key_path
        try:
            with open(self.local_key_path, 'r') as f:
                self.key = RSA.importKey(f.read())
                self.pub_key = self.key.publickey()
        except IOError:
            random_generator = Random.new().read
            self.key = RSA.generate(2048, random_generator)
            self.pub_key = self.key.publickey()

            self.register_key(self.pub_key)
            with open(self.local_key_path, 'w') as f:
                f.write(self.key.exportKey('PEM'))
                f.close()

    def register_key(self, pub_key):
        pass

    def encrypt(self, msg):
        return self.pub_key.encrypt(msg, 32)

    def decrypt(self, msg):
        return self.key.decrypt(msg)

    def sign(self, msg):
        h = SHA256.new()
        h.update(msg)
        signer = PKCS1_PSS.new(self.key)
        signature = signer.sign(h)

        return signature

    def verify(self, msg, signature, ext_pub_key=None):
        h = SHA256.new()
        h.update(msg)
        if ext_pub_key:
            verifier = PKCS1_PSS.new(ext_pub_key)
        else:
            verifier = PKCS1_PSS.new(self.key)

        return verifier.verify(h, signature)

    def re_encrypt(self, msg, ext_pub_key):
        msg_dec = self.decrypt(msg)

        return ext_pub_key.encrypt(msg_dec, 32)


class AESCipher(object):

    def __init__(self, key=None):
        self.key = key
        if not key:
            self.new_key()

    def new_key(self):
        self.key = Random.new().read(AES.key_size[2])

        return self.key

    def encrypt(self, msg):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)

        return iv + cipher.encrypt(msg)

    def decrypt(self, msg):
        iv = msg[0:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)

        return cipher.decrypt(msg[AES.block_size:])


class EncryptionException(Exception):
    def __init__(self, reason):
        self.reason = reason
