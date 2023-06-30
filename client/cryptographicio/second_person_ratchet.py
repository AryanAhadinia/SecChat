import base64

from client.cryptographicio import symmetric_ratchet.symmetric_ratchet
from client.cryptographicio import b64.b64
from client.cryptographicio import hkdf_.hkdf
from client.cryptographicio import padding.pad, padding.unpad

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Crypto.Cipher import AES


class SecondPerson(object):
    def __init__(self, shared_key):
        self.sk = shared_key
        self.DH_ratchet = X25519PrivateKey.generate()

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = symmetric_ratchet(self.sk)
        # initialise the sending and recving chains
        self.recv_ratchet = symmetric_ratchet(self.root_ratchet.next()[0])
        self.send_ratchet = symmetric_ratchet(self.root_ratchet.next()[0])

    def dh_ratchet_recv(self, first_person_public_key):
        # perform a DH ratchet rotation using Alice's public key
        dh_recv = self.DH_ratchet.exchange(first_person_public_key)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = symmetric_ratchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))

    def dh_ratchet_send(self, first_person_public_key):
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Alice
        self.DH_ratchet = X25519PrivateKey.generate()
        dh_send = self.DH_ratchet.exchange(first_person_public_key)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = symmetric_ratchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))
        return self.DH_ratchet.public_key()

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        # send ciphertext and current DH public key
        return cipher

    def recv(self, cipher, first_person_public_key):
        # receive Alice's new public key and use it to perform a DH
        self.dh_ratchet(first_person_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg)
        return msg
