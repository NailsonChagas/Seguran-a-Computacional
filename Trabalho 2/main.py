import os
from Crypto.Cipher import AES # key (bytes/bytearray/memoryview) – 16 (AES-128), 24 (AES-192) or 32 (AES-256) bytes long
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ECB e CBC trabalha com blocos fixos de 16 bytes por isso o pad

# CFB, OFB e CTR -> Esses modos transformam o AES em algo equivalente a uma stream cipher, ou seja:
# - Eles geram um fluxo de bytes (keystream)
# - E fazem XOR com o plaintext: plaintext XOR keystream = ciphertext
# - Como o XOR funciona byte a byte:
#     - Pode criptografar qualquer tamanho
#     - Não precisa completar bloco
#     - Pode parar em qualquer ponto

# 1. ECB (Electronic Codebook)
# Cifra cada bloco separadamente.
# - Vantagem: extremamente rapido
# - Problema: revela padrões (blocos iguais → saídas iguais)

# 2. CBC (Cipher Block Chaining)
# Usa um IV aleatório e encadeia os blocos
# - Vantagem: boa confidencialidade se o IV for realmente aleatório.
# - Problemas:
#     - Vulnerável a modificações (malleable)
#     - Não é seguro contra ataques mais fortes (CCA)
#     - Pode vazar dados com ataques de padding oracle
#     - Processamento sequencial (mais lento)

# 3. CFB (Cipher Feedback)
# Funciona como modo de fluxo (stream).
# - Vantagem: auto-sincronização (erros afetam só temporariamente)
# - Problemas:
#     - Ineficiente (processa poucos bits por vez)
#     - Sequencial e mais lento
#     - Também vulnerável a modificações

# 4. OFB (Output Feedback)
# Gera um fluxo de bits independente do texto.
# - Vantagem: não precisa de padding.
# - Problemas:
#     - Vulnerável a alterações
#     - Sequencial e lento
#     - Sem vantagens reais sobre CTR

# 5. CTR (Counter Mode)
# Usa um contador (nonce/IV) para gerar o fluxo.
# - Vantagens:
#     - Muito rápido (paralelizável)
#     - Seguro se o nonce NUNCA for reutilizado
#     - Base para criptografia moderna autenticada
# - Problema crítico: reutilizar nonce quebra totalmente a segurança.

root_path = "./"
valid_exts = (".pdf", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp")
encrypted_ext = ".aes"

# HEADER DO ARQUIVO:
# [1 byte: modo] + [dependendo do modo: IV ou nonce] + [ciphertext]
# CTR tem formato especial: [modo][tam_nonce][nonce][ciphertext]
modes = {
    "1": ("ECB", AES.MODE_ECB,
          "Não utiliza IV e cifra cada bloco de forma independente.\n"
          "\tIsso faz com que padrões no plaintext apareçam no ciphertext.\n"
          "\tNão é seguro para uso geral, sendo indicado apenas para fins didáticos."),

    "2": ("CBC", AES.MODE_CBC,
          "Utiliza um IV aleatório e encadeia os blocos de criptografia.\n"
          "\tOferece boa confidencialidade, mas não garante integridade dos dados.\n"
          "\tVulnerável a ataques como padding oracle se mal implementado."),

    "3": ("CFB", AES.MODE_CFB,
          "Modo baseado em feedback que transforma o bloco em fluxo (stream).\n"
          "\tSeguro se o IV for aleatório, mas não protege contra modificações.\n"
          "\tPossui propriedade de auto-sincronização em caso de perda de dados."),

    "4": ("OFB", AES.MODE_OFB,
          "Gera um fluxo de chave independente do ciphertext.\n"
          "\tErros não se propagam, mas alterações maliciosas não são detectadas.\n"
          "\tRequer IV único; reutilização compromete a segurança."),

    "5": ("CTR", AES.MODE_CTR,
          "Transforma o bloco em modo streaming usando contador (nonce + counter).\n"
          "\tAltamente eficiente e paralelizável.\n"
          "\tMuito seguro se o nonce nunca for reutilizado; caso contrário, a segurança é quebrada.")
}

while True:
    raw_files = []
    encrypted_files = []

    for item in os.listdir(root_path):
        full_path = os.path.join(root_path, item)

        if os.path.isfile(full_path):
            if item.lower().endswith(valid_exts):
                raw_files.append(full_path)
            elif item.lower().endswith(encrypted_ext):
                encrypted_files.append(full_path)

    selected_opt = input(
        "\nSelecione (e = encriptar / d = decriptar / s = sair): "
    ).lower()

    match selected_opt:
        case "s":
            break

        case "e":
            if not raw_files:
                print("Nenhum arquivo para encriptar.")
                continue
            selected_files = raw_files

        case "d":
            if not encrypted_files:
                print("Nenhum arquivo para descriptografar.")
                continue
            selected_files = encrypted_files

        case _:
            print("Opcao invalida.")
            continue

    # ---------------- TAMANHO DA CHAVE ----------------
    key_size = input("Escolha tamanho da chave (1 = 128 bits / 2 = 256 bits): ")

    match key_size:
        case "1":
            key_len = 16
        case "2":
            key_len = 32
        case _:
            print("Opcao invalida.")
            continue

    key_input = input(f"Digite uma chave de {key_len} caracteres: ")

    if len(key_input) != key_len:
        print(f"A chave deve ter exatamente {key_len} caracteres.")
        continue

    key = key_input.encode("utf-8")

    # ESCOLHA DO MODO APENAS PARA ENCRIPTAÇÃO
    if selected_opt == "e":
        print("\nSelecione o modo de operacao:")
        for k, v in modes.items():
            print(f"{k} - {v[0]}: {v[2]}")

        mode_choice = input("Opcao: ")

        if mode_choice not in modes:
            print("Modo invalido.")
            continue

        mode_name, mode, _ = modes[mode_choice]
        mode_id = int(mode_choice).to_bytes(1, 'big')

    # ---------------- SELECAO DE ARQUIVO ----------------
    print("\n----- Arquivos disponiveis: -----")
    for i, f in enumerate(selected_files):
        print(f"{i} - {f}")

    while True:
        try:
            num_file = int(input("Selecione o numero do arquivo: "))
            if 0 <= num_file < len(selected_files):
                selected_file = selected_files[num_file]
                break
            else:
                print("Numero invalido.")
        except ValueError:
            print("Digite um numero valido.")

    print(f"\nArquivo selecionado: {selected_file}")

    # ---------------- ENCRIPTAR ----------------
    if selected_opt == "e":
        with open(selected_file, "rb") as f:
            data = f.read()

        match mode:
            case AES.MODE_ECB:
                cipher = AES.new(key, mode)
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
                final_data = mode_id + encrypted_data

            case AES.MODE_CBC:
                iv = get_random_bytes(16)
                cipher = AES.new(key, mode, iv=iv)
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
                final_data = mode_id + iv + encrypted_data

            case AES.MODE_CFB:
                iv = get_random_bytes(16)
                cipher = AES.new(key, mode, iv=iv)
                encrypted_data = cipher.encrypt(data)
                final_data = mode_id + iv + encrypted_data

            case AES.MODE_OFB:
                iv = get_random_bytes(16)
                cipher = AES.new(key, mode, iv=iv)
                encrypted_data = cipher.encrypt(data)
                final_data = mode_id + iv + encrypted_data

            case AES.MODE_CTR:
                cipher = AES.new(key, mode)
                nonce = cipher.nonce

                print("Nonce (hex):", " ".join(f"{b:02x}" for b in nonce))
                print(f"Tamanho do nonce: {len(nonce)} bytes")

                encrypted_data = cipher.encrypt(data)
                final_data = mode_id + len(nonce).to_bytes(1, 'big') + nonce + encrypted_data

            case _:
                print("Modo nao suportado.")
                continue

        output_file = selected_file + encrypted_ext

        with open(output_file, "wb") as f:
            f.write(final_data)

        print(f"Arquivo criptografado salvo em: {output_file}")

    # ---------------- DECRIPTAR ----------------
    elif selected_opt == "d":
        with open(selected_file, "rb") as f:
            data = f.read()

        mode_id = data[0]

        if str(mode_id) not in modes:
            print("Modo inválido no arquivo.")
            continue

        mode = modes[str(mode_id)][1]
        offset = 1

        match mode:
            case AES.MODE_ECB:
                ciphertext = data[offset:]
                cipher = AES.new(key, mode)
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            case AES.MODE_CBC:
                iv = data[offset:offset+16]
                ciphertext = data[offset+16:]
                cipher = AES.new(key, mode, iv=iv)
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            case AES.MODE_CFB | AES.MODE_OFB:
                iv = data[offset:offset+16]
                ciphertext = data[offset+16:]
                cipher = AES.new(key, mode, iv=iv)
                decrypted_data = cipher.decrypt(ciphertext)

            case AES.MODE_CTR:
                nonce_size = data[offset]
                offset += 1

                nonce = data[offset:offset+nonce_size]
                ciphertext = data[offset+nonce_size:]

                cipher = AES.new(key, mode, nonce=nonce)
                decrypted_data = cipher.decrypt(ciphertext)

            case _:
                print("Modo nao suportado.")
                continue

        dir_name = os.path.dirname(selected_file)
        file_name = os.path.basename(selected_file).replace(encrypted_ext, "")
        output_file = os.path.join(dir_name, "decrypted_" + file_name)

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"Arquivo descriptografado salvo em: {output_file}")