from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import struct
import os

# =========================================================
# CHAVES GLOBAIS
# =========================================================

# gera chave privada RSA (usada na 3 e 4)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# chave pública correspondente (usada na 3 e 4)
public_key = private_key.public_key()

# chave simétrica AES (derivada de uma string fixa)
# usada para criptografia com AES-GCM
key = hashlib.sha256(b"AAAAAAAAAAAAAAAAAAAAA").digest()

# salt global
salt = "BBBBBBBBBBBBBBB"

# =========================================================
# OBS:
# public_key.verify:
# - usa a chave pública
# - verifica se a assinatura foi gerada com a chave privada
# - qualquer alteração no arquivo invalida a assinatura
# =========================================================


# =========================================================
# LEITURA DE ARQUIVO
# =========================================================
def read_file(input_file_path: str) -> tuple[bytes, bytes]:
    # abre arquivo em modo binário
    with open(input_file_path, "rb") as f:
        file_data = f.read()

    # extrai apenas o nome do arquivo (sem caminho)
    file_name = os.path.basename(input_file_path).encode()

    return file_name, file_data


# =========================================================
# HASH (SHA-512)
# =========================================================
def compute_hash(data: bytes) -> bytes:
    # calcula hash criptográfico do conteúdo
    return hashlib.sha512(data).digest()


# =========================================================
# SERIALIZAÇÃO
# Converte dados estruturados em bytes
# =========================================================
def serialize_payload(file_name: bytes, hash_bytes: bytes, file_data: bytes) -> bytes:
    return (
        # tamanho do nome
        struct.pack(">I", len(file_name)) +
        file_name +

        # tamanho do campo de hash
        struct.pack(">I", len(hash_bytes)) +
        hash_bytes +

        # tamanho do arquivo
        struct.pack(">Q", len(file_data)) +
        file_data
    )


# =========================================================
# DESSERIALIZAÇÃO
# Reconstrói os dados a partir dos bytes
# =========================================================
def deserialize_payload(payload: bytes):
    offset = 0

    # lê tamanho do nome
    name_len = struct.unpack(">I", payload[offset:offset+4])[0]
    offset += 4

    # lê nome
    file_name = payload[offset:offset+name_len].decode()
    offset += name_len

    # lê tamanho do campo hash
    hash_len = struct.unpack(">I", payload[offset:offset+4])[0]
    offset += 4

    # lê hash ou assinatura (campo genérico)
    hash_field = payload[offset:offset+hash_len]
    offset += hash_len

    # lê tamanho do arquivo
    file_len = struct.unpack(">Q", payload[offset:offset+8])[0]
    offset += 8

    # lê dados do arquivo
    file_data = payload[offset:offset+file_len]

    return file_name, hash_field, file_data


# =========================================================
# AES ENCRYPT (AES-GCM)
# Garante: confidencialidade + integridade autenticada
# =========================================================
def aes_encrypt(data: bytes, key: bytes) -> bytes:
    # inicializa AES-GCM com chave
    aesgcm = AESGCM(key) # 256 bits

    # gera nonce aleatório (12 bytes padrão)
    nonce = os.urandom(12) # valor único por criptografia, usado junto com a chave

    # retorna nonce + dados criptografados
    return nonce + aesgcm.encrypt(nonce, data, None)


# =========================================================
# AES DECRYPT
# =========================================================
def aes_decrypt(data: bytes, key: bytes) -> bytes:
    # separa nonce e ciphertext
    nonce = data[:12]
    ciphertext = data[12:]

    # inicializa AES-GCM
    aesgcm = AESGCM(key)

    # descriptografa (também valida integridade)
    return aesgcm.decrypt(nonce, ciphertext, None)