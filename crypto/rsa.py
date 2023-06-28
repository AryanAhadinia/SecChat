import rsa


def generate_keypair():
    return rsa.newkeys(1024)


def write_keys(pu, pr, path):
    with open(path / "rsa.pub", "wb") as p:
        p.write(pu.save_pkcs1("PEM"))
    with open(path / "rsa.pem", "wb") as p:
        p.write(pr.save_pkcs1("PEM"))


def load_private_key(path):
    with open(path / "rsa.pem", "rb") as p:
        return rsa.PrivateKey.load_pkcs1(p.read())


def load_public_key(path):
    with open(path / "rsa.pub", "rb") as p:
        return rsa.PublicKey.load_pkcs1(p.read())


def encrypt(message, pu):
    blocks = [message[i:i + 117] for i in range(0, len(message), 117)]
    ciphertext = b""
    for block in blocks:
        ciphertext += rsa.encrypt(block.encode(), pu)
    return ciphertext


def decrypt(ciphertext, pr):
    blocks = [ciphertext[i:i + 128] for i in range(0, len(ciphertext), 128)]
    message = b""
    for block in blocks:
        message += rsa.decrypt(block, pr)
    return message.decode()


def sign(message, pr):
    return rsa.sign(message.encode(), pr, "SHA-1")


def verify(message, signature, pu):
    try:
        return rsa.verify(message.encode(), signature, pu) == "SHA-1"
    except:
        return False
