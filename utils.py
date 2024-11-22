import base64 as b64
import os

import bcrypt
import hashlib
from datetime import timezone, datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import pkcs12




def join_pair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y


def get_userdata(p12_fname, password: str = None):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(
        p12, password.encode("utf-8") if password else None
    )
    return (private_key, user_cert, ca_cert)

def get_timestamp():
    return datetime.now().astimezone(tz=timezone.utc) + timedelta(hours=1)

def encrypt_message(message: bytes, aesgcm: AESGCM) -> bytes:
    nonce = os.urandom(12)
    ciphertext = nonce + aesgcm.encrypt(nonce, message, None)
    return ciphertext


def decrypt_message(ciphertext: bytes, aesgcm: AESGCM) -> bytes:
    nonce = ciphertext[:12]
    message = aesgcm.decrypt(nonce, ciphertext[12:], None)
    return message


def verify_signature(signature, pub_key, data):
    try:
        pub_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return b64.b64encode(hashed_password).decode("utf-8")


def check_password(password: str, hashed_password: str):
    return bcrypt.checkpw(
        password.encode("utf-8"), b64.b64decode(hashed_password.encode("utf-8"))
    )


def generate_hkdf_key(length):
    init_key = os.urandom(length)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(init_key)

def save_to_file(filename, data):
    with open(filename, "w") as f:
        f.write(data)

def calculate_message_hash(message):

    if isinstance(message, str):
        message_bytes = message.encode()
    elif isinstance(message, bytes):
        message_bytes = message

    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    return digest.finalize()
