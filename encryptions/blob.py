# the event ids are now encrypted and called "fingerprint_blob"
# this is the encryption algorithm used to encrypt the fingerprint_blob

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets
import base64


def encrypt(encryption_key: str, data: str):
    key_bytes = bytes.fromhex(encryption_key)
    nonce = secrets.token_bytes(16)
    aes_cipher = AES.new(key_bytes, AES.MODE_CBC, nonce)
    encrypted_bytes = aes_cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(nonce).decode() + "." + base64.b64encode(encrypted_bytes).decode()


def decrypt(encryption_key: str, data: str):
    key_bytes = bytes.fromhex(encryption_key)
    nonce, encrypted_bytes = map(base64.b64decode, data.split("."))
    aes_cipher = AES.new(key_bytes, AES.MODE_CBC, nonce)
    plain_bytes = unpad(aes_cipher.decrypt(encrypted_bytes), AES.block_size)
    return plain_bytes.decode("utf-8")
