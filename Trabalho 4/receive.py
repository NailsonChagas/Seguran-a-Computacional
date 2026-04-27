from aux import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# =========================================================
# EXERCICIO 1
# AES + HASH
# Garante: confidencialidade + integridade
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
# Garante: integridade (sem confidencialidade do arquivo)
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
# ASSINATURA DIGITAL (RSA)
# Garante: autenticidade + integridade
# =========================================================
def exercicio3_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        payload = f.read()

    # extrai assinatura e dados
    file_name, signature, file_data = deserialize_payload(payload)

    # recalcula hash do arquivo
    hash_bytes = compute_hash(file_data)

    try:
        # verifica assinatura com chave pública
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("ok (assinatura válida)")

    except Exception:
        print("assinatura inválida")
        return

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 4
# ASSINATURA + AES
# Garante: confidencialidade + autenticidade + integridade
# =========================================================
def exercicio4_receive(encrypted_file_path: str, key: bytes, output_dir: str = ".") -> str:
    with open(encrypted_file_path, "rb") as f:
        encrypted = f.read()

    # primeiro descriptografa o conteúdo
    payload = aes_decrypt(encrypted, key)

    # extrai assinatura e dados
    file_name, signature, file_data = deserialize_payload(payload)

    hash_bytes = compute_hash(file_data)

    try:
        # valida assinatura
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("ok (assinatura válida + conteúdo íntegro)")

    except Exception:
        print("assinatura inválida ou dados corrompidos")
        return

    output_file_path = os.path.join(output_dir, file_name)

    with open(output_file_path, "wb") as f:
        f.write(file_data)
        os.remove(encrypted_file_path)

    return output_file_path


# =========================================================
# EXERCICIO 5
# HASH com SALT (sem proteção do arquivo)
# Garante: integridade com salt
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
# Garante: confidencialidade + integridade com salt
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