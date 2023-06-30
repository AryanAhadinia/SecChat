import base64
import json
from cryptographicio.aes import AESCipher
from cryptographicio.rsa_ import encrypt, decrypt, sign, verify


def proto_encrypt(
    message: str, token: str, aes_key: bytes, self_private_key, other_public_key
):
    content = {
        "message": message,
        "signature": base64.b64encode(sign(message, self_private_key)).decode(),
    }
    content_json = json.dumps(content)
    aes_ = AESCipher(aes_key)
    packet = {
        "content_json": base64.b64encode(aes_.encrypt(content_json)).decode(),
        "token": base64.b64encode(encrypt(token, other_public_key)).decode(),
    }
    return base64.b64encode(json.dumps(packet).encode()).decode()

def proto_get_token(packet:str, self_private_key):
    packet = json.loads(base64.b64decode(packet.encode()).decode())
    return decrypt(
        base64.b64decode(packet["token"].encode()), self_private_key
    )
def proto_decrypt(packet: str, aes_key: bytes, self_private_key, other_public_key):
    packet = json.loads(base64.b64decode(packet.encode()).decode())
    aes_ = AESCipher(aes_key)
    content_json = aes_.decrypt(base64.b64decode(packet["content_json"].encode()))
    content = json.loads(content_json)
    if not verify(
        content["message"],
        base64.b64decode(content["signature"].encode()),
        other_public_key,
    ):
        raise Exception("Invalid signature")
    return content["message"]
