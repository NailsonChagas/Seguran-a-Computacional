from aux import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# =========================================================
# EXERCICIO 1
# AES + HASH
# =========================================================
def exercicio1_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    # lê arquivo criptografado
    with open(encrypted_file_path, "rb") as f:
        encrypted = f.read()

    # descriptografa usando AES
    payload = aes_decrypt(encrypted, key)

    # extrai nome, hash armazenado e dados
    file_name, stored_hash, file_data = deserialize_payload(payload)

    # verifica integridade comparando hashes
    if compute_hash(file_data) != stored_hash:
        print("hash mismatch")
        return
    else:
        print("ok")

    # salva arquivo original
    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 2
# HASH criptografado com AES
# =========================================================
def exercicio2_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        payload = f.read()

    # extrai hash criptografado e dados
    file_name, encrypted_hash, file_data = deserialize_payload(payload)

    # descriptografa o hash
    stored_hash = aes_decrypt(encrypted_hash, key)

    # valida integridade
    if compute_hash(file_data) != stored_hash:
        print("hash mismatch")
        return
    else:
        print("ok")

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 3
# HASH com RSA
# =========================================================
def exercicio3_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        payload = f.read()

    file_name, encrypted_hash, file_data = deserialize_payload(payload)

    # descriptografa hash com chave privada
    decrypted_hash = private_key.decrypt(
        encrypted_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # recalcula hash
    hash_bytes = compute_hash(file_data)

    if decrypted_hash == hash_bytes:
        print("ok (integridade válida)")
    else:
        print("dados corrompidos")
        return

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path

# =========================================================
# EXERCICIO 4
#  HASH com RSA + AES
# =========================================================
def exercicio4_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        encrypted = f.read()

    # descriptografa AES
    payload = aes_decrypt(encrypted, key)

    # extrai dados
    file_name, encrypted_hash, file_data = deserialize_payload(payload)

    # descriptografa hash com chave privada
    decrypted_hash = private_key.decrypt(
        encrypted_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # recalcula hash
    hash_bytes = compute_hash(file_data)

    if decrypted_hash == hash_bytes:
        print("ok (integridade válida + confidencialidade)")
    else:
        print("dados corrompidos")
        return

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path

# =========================================================
# EXERCICIO 5
# HASH com SALT (sem proteção do arquivo)
# =========================================================
def exercicio5_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        encrypted = f.read()

    # descriptografa
    payload = aes_decrypt(encrypted, key)

    file_name, stored_hash, file_data = deserialize_payload(payload)

    # usa salt global
    salt_bytes = salt.encode()

    # recalcula hash com salt
    computed_hash = compute_hash(file_data + salt_bytes)

    if computed_hash != stored_hash:
        print("hash mismatch")
        return
    else:
        print("ok (hash + salt válido)")

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 6
# HASH com SALT + AES
# =========================================================
def exercicio6_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        encrypted = f.read()

    # descriptografa tudo
    payload = aes_decrypt(encrypted, key)

    file_name, stored_hash, file_data = deserialize_payload(payload)

    salt_bytes = salt.encode()

    # recalcula hash com salt
    computed_hash = compute_hash(file_data + salt_bytes)

    if computed_hash != stored_hash:
        print("hash mismatch")
        return
    else:
        print("ok (confidencialidade + integridade com salt)")

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path