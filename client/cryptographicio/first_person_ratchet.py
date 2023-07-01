from cryptographicio.symmetric_ratchet import SymmetricRatchet
from cryptographicio.b64 import b64
from cryptographicio.hkdf_ import hkdf
from cryptographicio.padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Crypto.Cipher import AES


class FirstPerson(object):
    def __init__(self, shared_key):
        self.sk = shared_key
        self.DHratchet = None
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

    def dh_ratchet_send(self, second_person_public):
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(second_person_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print('Send ratchet seed:', b64(shared_send))
        return self.DHratchet.public_key()

    def dh_ratchet_recv(self, second_person_public):
        if self.DHratchet is not None:
            dh_recv = self.DHratchet.exchange(second_person_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            self.recv_ratchet = SymmetricRatchet(shared_recv)
            print('Recv ratchet seed:', b64(shared_recv))

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('Sending ciphertext to Second:', b64(cipher))
        return cipher

    def recv(self, cipher, second_person_public_key):
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('Decrypted message from Second:', msg)
        return msg
