from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import struct
import os

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
key = hashlib.sha256(b"AAAAAAAAAAAAAAAAAAAAA").digest()
salt = "BBBBBBBBBBBBBBB"

# public_key.verify
# Usa a chave pública
# Verifica se a assinatura foi gerada a partir daquele hash
# Se qualquer bit do arquivo mudar, o hash muda -> a verificação falha

def read_file(input_file_path: str) -> tuple[bytes, bytes]:
    with open(input_file_path, "rb") as f:
        file_data = f.read()

    file_name = os.path.basename(input_file_path).encode()
    return file_name, file_data


def compute_hash(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def serialize_payload(file_name: bytes, hash_bytes: bytes, file_data: bytes) -> bytes:
    return (
        struct.pack(">I", len(file_name)) +
        file_name +
        struct.pack(">I", len(hash_bytes)) +
        hash_bytes +
        struct.pack(">Q", len(file_data)) +
        file_data
    )


def deserialize_payload(payload: bytes):
    offset = 0

    name_len = struct.unpack(">I", payload[offset:offset+4])[0]
    offset += 4

    file_name = payload[offset:offset+name_len].decode()
    offset += name_len

    hash_len = struct.unpack(">I", payload[offset:offset+4])[0]
    offset += 4

    hash_field = payload[offset:offset+hash_len]  # <- genérico agora
    offset += hash_len

    file_len = struct.unpack(">Q", payload[offset:offset+8])[0]
    offset += 8

    file_data = payload[offset:offset+file_len]

    return file_name, hash_field, file_data


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)