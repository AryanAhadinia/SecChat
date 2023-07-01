from cryptographicio.symmetric_ratchet import SymmetricRatchet
from cryptographicio.b64 import b64
from cryptographicio.hkdf_ import hkdf
from cryptographicio.padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Crypto.Cipher import AES


class SecondPerson(object):
    def __init__(self, shared_key):
        self.sk = shared_key
        self.DH_ratchet = X25519PrivateKey.generate()
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

    def dh_ratchet_recv(self, first_person_public_key):
        dh_recv = self.DH_ratchet.exchange(first_person_public_key)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print('Recv ratchet seed:', b64(shared_recv))

    def dh_ratchet_send(self, first_person_public_key):
        self.DH_ratchet = X25519PrivateKey.generate()
        dh_send = self.DH_ratchet.exchange(first_person_public_key)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print('Send ratchet seed:', b64(shared_send))
        return self.DH_ratchet.public_key()

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('Sending ciphertext to First:', b64(cipher))
        return cipher

    def recv(self, cipher, first_person_public_key):
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('Decrypted message from First:', msg)
        return msg
