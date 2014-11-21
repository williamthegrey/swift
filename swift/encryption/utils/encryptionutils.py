import random
from Crypto.Cipher import AES


def encrypt(key, in_str):
    """ Encrypts a file using AES (CBC mode) with the given key.
        key:The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.
    """
    chunk_size = 64 * 1024
    out_str = ""
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    out_str = out_str + iv
    for chunk in chunks(in_str, chunk_size, 0):
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            chunk += ' ' * (16 - len(chunk) % 16)
        out_str = out_str + encryptor.encrypt(chunk)
    return out_str


def decrypt(key, in_str):
    chunk_size=24 * 1024
    out_str = ""
    iv = in_str[0:16]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    for chunk in chunks(in_str, chunk_size, 16):
        if len(chunk) == 0:
                break
        out_str = out_str + decryptor.decrypt(chunk)
    return out_str


def chunks(s, n, st):
    for start in range(st,len(s),n):
        yield s[start:start+n]
