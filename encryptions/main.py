# main encryption algorithm used to encrypt fingerprint

from Crypto.Cipher import AES
import base64
import secrets


def encrypt(encryption_key: str, data: str):
    key_bytes = bytes.fromhex(encryption_key)
    nonce = secrets.token_bytes(12)
    aes_cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = aes_cipher.encrypt_and_digest(data.encode())
    combined = ciphertext + auth_tag + nonce + b"\x00"
    return base64.b64encode(combined).decode()


def decrypt(encryption_key: str, data: str):
    key_bytes = bytes.fromhex(encryption_key)
    decoded_data = base64.b64decode(data)
    ciphertext = decoded_data[:-29]
    auth_tag = decoded_data[-29:-13]
    nonce = decoded_data[-13:-1]
    aes_cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return aes_cipher.decrypt_and_verify(ciphertext, auth_tag).decode()
