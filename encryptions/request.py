# the request payload and response are also encrypted and have different keys
# this is the encryption algorithm used to encrypt the request payload and response

from Crypto.Cipher import AES
import secrets
import msgpack
import json


# encrypt payload
def encrypt(encryption_key: str, data: dict, config: dict) -> bytes:
    key_bytes = bytes.fromhex(encryption_key)
    nonce = secrets.token_bytes(12)
    aes_cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    encrypted_data, auth_tag = aes_cipher.encrypt_and_digest(msgpack.packb(data))
    data = msgpack.ExtType(18, nonce + encrypted_data + auth_tag)
    return msgpack.packb([json.dumps(config, separators=(",", ":")), data])


# decrypt response
def decrypt(encryption_key: str, data: bytes) -> dict:
    key_bytes = bytes.fromhex(encryption_key)
    nonce = data[:12]
    encrypted_data = data[12:-16]
    auth_tag = data[-16:]
    aes_cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    decrypted = aes_cipher.decrypt_and_verify(encrypted_data, auth_tag)
    return msgpack.unpackb(decrypted, strict_map_key=False)
