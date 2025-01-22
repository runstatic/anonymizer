import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

"""Script defining SymmetricEncryption class"""


class SymmetricEncryption(object):
    """
    SymmetricEncryption is a class for AES-ECB encryption with a 256Bit Key.

    Encryption needs to produce the same output for linkability.
    """

    def __init__(self, key):
        """
        Create a SymmetricEncryption object.

        :param key: secret using for encryption and decryption
        """
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: str) -> str:
        """
        Encrypt a target string.

        :param raw: string to encrypt
        :return: encoding base64 of the encrypted string
        """
        raw = pad(raw.encode("utf-8"), 16, style="pkcs7")
        cipher = AES.new(self.key, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, enc: str) -> str:
        """
        Decrypt a target string.

        :param enc: base64 encoding of the encrypted string
        :return: decrypted string
        """
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return unpad(cipher.decrypt(enc), 16, style="pkcs7").decode("utf-8")
