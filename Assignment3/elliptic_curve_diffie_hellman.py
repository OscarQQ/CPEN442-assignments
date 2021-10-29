from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECDH:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.key_length = 32

    def get_public_key(self):
        return self.private_key.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint).hex()

    def get_shared_key(self, encoded_string):
        shared_key = self.private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP384R1(), data=bytes.fromhex(encoded_string)))
        return HKDF(algorithm=hashes.SHA256(),length=self.key_length,salt=None,info=b'',).derive(shared_key)
