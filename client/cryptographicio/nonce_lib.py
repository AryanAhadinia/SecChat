import random
import string

N = 40


def generate_nonce():
    ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
