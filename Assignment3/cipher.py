import base64
from Cryptodome.Cipher import AES
import hashlib

class Cipher:
    def _get_cipher(key : str):
        # str to bytes
        key = key.encode("utf-8")
        # force key to be 256 bits by getting sha256 hash
        key = hashlib.sha256(key).digest()
        # use mode cbc-mac + counter (mode_ccm) for integrity and encryption
        # add 11-byte nonce
        return AES.new(key, AES.MODE_CCM, nonce=b"eleven byte")

    def encrypt(plaintext : bytes, key : str) -> str:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        # encrypt plain bytes to cipher bytes
        ciphertext = Cipher._get_cipher(key).encrypt(plaintext)
        # base64-encode cipher bytes to cipher str
        return base64.encodebytes(ciphertext).decode("utf-8")

    def decrypt(ciphertext : bytes, key : str) -> bytes:
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode("utf-8")
        # base64-decode cipher str to cipher bytes
        ciphertext = base64.decodebytes(ciphertext)
        # decrypt cipher bytes to plain bytes
        return Cipher._get_cipher(key).decrypt(ciphertext)