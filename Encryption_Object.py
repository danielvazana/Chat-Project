import hashlib
import random
import string
import base64
import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import new as Random
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
from base64 import b64encode


class AESEncryption:

    BS = 32

    def __init__(self, aes_generate=True):
        if aes_generate:
            self.key = os.urandom(16)
        else:
            self.key = b''
    
    def get_key(self):
        return b64encode(self.key).decode('ascii')
    
    def set_key(self, key):
        self.key = b64decode(key)

    def encrypt(self, raw):
        raw = self.pad(raw)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc.encode())
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:])).decode('utf8')

    def unpad(self, s):
        return s[0:-ord(s[-1:])]

    def pad(self, s):
        return bytes(s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS), 'utf-8')

class RSAEncryption:
    def __init__(self, generate_key=True):
        if generate_key:
            rng = Random().read
            self.key = RSA.generate(1024,rng)
        else:
            self.key = b''
    
    def get_publickey(self):
        return self.key.publickey().exportKey('PEM')
    
    def set_publickey(self, key):
        self.key = RSA.importKey(key)

    def encrypt(self,data):
        plaintext = b64encode(data.encode())
        rsa_encryption_cipher = PKCS1_v1_5.new(self.key)
        ciphertext = rsa_encryption_cipher.encrypt(plaintext)
        return b64encode(ciphertext).decode()

    def decrypt(self,data):
        ciphertext = b64decode(data)
        rsa_decryption_cipher = PKCS1_v1_5.new(self.key)
        plaintext = rsa_decryption_cipher.decrypt(ciphertext,16)
        return b64decode(plaintext).decode()


if __name__ == "__main__":
    aes1 = AESEncryption()
    aes2 = AESEncryption(False)
    rsa1 = RSAEncryption(False)
    rsa2 = RSAEncryption()
    public_key = rsa2.get_publickey()
    rsa1.set_publickey(public_key)
    print(rsa1.get_publickey() == rsa2.get_publickey())
    key = rsa1.encrypt(aes1.get_key())
    aes2.set_key(rsa2.decrypt(key))
    print(aes2.get_key() == aes1.get_key())