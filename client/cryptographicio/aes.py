import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import os


class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        print(type(key))
        if type(key) == bytes:
            self.key = key
        else:
            self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size :])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1 :])]
    
    @staticmethod
    def _keygen():
        return os.urandom(32)


def recrypt(data, old_key, new_key):
    old_aes = AESCipher(old_key)
    new_aes = AESCipher(new_key)
    return new_aes.encrypt(old_aes.decrypt(data))
