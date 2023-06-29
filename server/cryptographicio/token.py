import random
import string

N = 30


def generate_token():
    ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
