from aux import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# =========================================================
# EXERCICIO 1
# AES + HASH
# =========================================================
def exercicio1_send(input_file_path: str, key: bytes) -> str:
    # lê arquivo
    file_name, file_data = read_file(input_file_path)

    # gera hash do conteúdo
    hash_bytes = compute_hash(file_data)

    # empacota nome + hash + dados
    payload = serialize_payload(file_name, hash_bytes, file_data)

    # criptografa tudo com AES
    encrypted = aes_encrypt(payload, key)

    output_file_path = f"{input_file_path}_enc"

    # salva arquivo criptografado e remove original
    with open(output_file_path, "wb") as f:
        f.write(encrypted)
        os.remove(input_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 2
# HASH criptografado (arquivo em claro)
# =========================================================
def exercicio2_send(input_file_path: str, key: bytes) -> str:
    file_name, file_data = read_file(input_file_path)

    # gera hash
    hash_bytes = compute_hash(file_data)

    # criptografa apenas o hash
    encrypted_hash = aes_encrypt(hash_bytes, key)

    # payload contém hash protegido + arquivo em claro
    payload = serialize_payload(file_name, encrypted_hash, file_data)

    output_file_path = f"{input_file_path}_enc"

    with open(output_file_path, "wb") as f:
        f.write(payload)
        os.remove(input_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 3
# ASSINATURA DIGITAL (RSA)
# =========================================================
def exercicio3_send(input_file_path: str, key: bytes) -> str:
    file_name, file_data = read_file(input_file_path)

    # gera hash (opcional, se quiser checar integridade depois)
    hash_bytes = compute_hash(file_data)

    # criptografa o hash com chave pública
    encrypted_hash = public_key.encrypt(
        hash_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # payload = hash criptografado + dados
    payload = serialize_payload(file_name, encrypted_hash, file_data)

    output_file_path = f"{input_file_path}_enc"

    with open(output_file_path, "wb") as f:
        f.write(payload)
        os.remove(input_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 4
# ASSINATURA + AES
# =========================================================
def exercicio4_send(input_file_path: str, key: bytes) -> str:
    file_name, file_data = read_file(input_file_path)

    # gera hash
    hash_bytes = compute_hash(file_data)

    # criptografa o hash com a chave pública (igual exercicio 3)
    encrypted_hash = public_key.encrypt(
        hash_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # monta payload
    payload = serialize_payload(file_name, encrypted_hash, file_data)

    # criptografa tudo com AES
    encrypted = aes_encrypt(payload, key)

    output_file_path = f"{input_file_path}_enc"

    with open(output_file_path, "wb") as f:
        f.write(encrypted)
        os.remove(input_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 5
# HASH com SALT + AES
# =========================================================
def exercicio5_send(input_file_path: str, key: bytes) -> str:
    file_name, file_data = read_file(input_file_path)

    # usa salt global
    salt_bytes = salt.encode()

    # gera hash com salt
    hash_bytes = compute_hash(file_data + salt_bytes)

    # empacota dados
    payload = serialize_payload(file_name, hash_bytes, file_data)

    # criptografa tudo
    encrypted = payload #aes_encrypt(payload, key)

    output_file_path = f"{input_file_path}_enc"

    with open(output_file_path, "wb") as f:
        f.write(encrypted)
        os.remove(input_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 6
# HASH com SALT + AES
# =========================================================
def exercicio6_send(input_file_path: str, key: bytes) -> str:
    file_name, file_data = read_file(input_file_path)

    salt_bytes = salt.encode()

    # hash com salt
    hash_bytes = compute_hash(file_data + salt_bytes)

    # monta payload
    payload = serialize_payload(file_name, hash_bytes, file_data)

    # criptografa com AES
    encrypted = aes_encrypt(payload, key)

    output_file_path = f"{input_file_path}_enc"

    with open(output_file_path, "wb") as f:
        f.write(encrypted)
        os.remove(input_file_path)

    return output_file_path