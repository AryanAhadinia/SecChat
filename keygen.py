from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os


def main():
    private_key_pass = input("Enter password for private key: ").encode()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass),
    )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    os.mkdir("server/keys")
    os.mkdir("client/keys")

    with open("server/keys/rsa.pem", "w") as private_key_file:
        private_key_file.write(encrypted_pem_private_key.decode())

    with open("server/keys/rsa.pub", "w") as public_key_file:
        public_key_file.write(pem_public_key.decode())

    with open("client/keys/rsa.pub", "w") as public_key_file:
        public_key_file.write(pem_public_key.decode())


if __name__ == "__main__":
    main()
