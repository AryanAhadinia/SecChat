from cryptographicio import hkdf_


class SymmetricRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf_.hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv
