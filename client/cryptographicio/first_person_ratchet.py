from client.cryptographicio import symmetric_ratchet.symmetric_ratchet
from client.cryptographicio import b64.b64
from client.cryptographicio import hkdf_.hkdf
from client.cryptographicio import padding.pad, padding.unpad

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Crypto.Cipher import AES


class FirstPerson(object):
    def __init__(self, shared_key):
        self.sk = shared_key
        self.DHratchet = None

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = symmetric_ratchet(self.sk)
        # initialise the sending and recving chains
        self.send_ratchet = symmetric_ratchet(self.root_ratchet.next()[0])
        self.recv_ratchet = symmetric_ratchet(self.root_ratchet.next()[0])

    def dh_ratchet_send(self, second_person_public):
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(second_person_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = symmetric_ratchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))
        return self.DHratchet.public_key()

    def dh_ratchet_recv(self, second_person_public):
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(second_person_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = symmetric_ratchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        return cipher

    def recv(self, cipher, second_person_public_key):
        # receive Bob's new public key and use it to perform a DH
        self.dh_ratchet(second_person_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Alice]\tDecrypted message:', msg)
        return msg

