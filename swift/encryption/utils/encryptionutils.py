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
        except IOError:
            random_generator = Random.new().read
            key = RSA.generate(2048, random_generator)
            with open(self.local_key_path, 'w') as f:
                f.write(key.exportKey('PEM'))
                f.close()
            self.key = key

        self.pub_key = self.key.publickey()

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

    def verify(self, msg, signature):
        h = SHA256.new()
        h.update(msg)
        verifier = PKCS1_PSS.new(self.key)

        return verifier.verify(h, signature)

    def re_encrypt(self, msg, ext_pub_key):
        msg_dec = self.decrypt(msg)

        return ext_pub_key.encrypt(msg_dec, 32)


class AESCipher(object):

    def __init__(self, key=None):
        self.key = key

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


def encrypt_sign(local_key_path, msg):
    aes_cipher = AESCipher()
    rsa_cipher = RSACipher(local_key_path)

    aes_cipher.new_key()
    key = rsa_cipher.encrypt(aes_cipher.key)
    msg_enc = aes_cipher.encrypt(msg)
    signature = rsa_cipher.sign(msg_enc)

    return {'msg': msg_enc, 'signature': signature, 'key': key}


def verify_decrypt(local_key_path, msg, signature, key):
    rsa_cipher = RSACipher(local_key_path)
    aes_cipher = AESCipher()

    if rsa_cipher.verify(msg, signature):
        aes_cipher.key = rsa_cipher.decrypt(key)
        return aes_cipher.decrypt(msg)
    else:
        raise EncryptionException('The message is corrupted.')


def re_encrypt(local_key_path, key, ext_pub_key):
    rsa_cipher = RSACipher(local_key_path)

    return rsa_cipher.re_encrypt(key, ext_pub_key)


class EncryptionException(Exception):
    def __init__(self, reason):
        self.reason = reason


def encrypt(key, in_str):
    """ Encrypts a file using AES (CBC mode) with the given key.
        key:The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.
    """
    chunk_size = 64 * 1024
    out_str = ""
    #iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    # TODO: hard code
    iv = '0123456789abcdef'
    # hard code ends

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    extra_space = 16 - len(in_str) % 16
    if extra_space < 10:
        extra_space = str(extra_space).rjust(2, '0')
    out_str = out_str + str(extra_space) + iv
    for chunk in _chunks(in_str, chunk_size, 0):
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            chunk += ' ' * (16 - len(chunk) % 16)
        out_str = out_str + encryptor.encrypt(chunk)
    return out_str


def decrypt(key, in_str):
    chunk_size = 24 * 1024
    out_str = ""
    extra_space = int(in_str[0:2]) % 16
    iv = in_str[2:18]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    for chunk in _chunks(in_str, chunk_size, 18):
        if len(chunk) == 0:
                break
        out_str = out_str + decryptor.decrypt(chunk)
        out_str = out_str[0:len(out_str)-extra_space]
    return out_str


def _chunks(s, n, st):
    for start in range(st, len(s), n):
        yield s[start:start+n]
