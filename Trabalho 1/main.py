import os
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad

root_path = "./"
valid_exts = (".pdf", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp")
encrypted_ext = ".hex"

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
        "Selecione (e = encriptar arquivo / d = decriptar arquivo / es = encriptar string / ds = decriptar string / s = sair): "
    ).lower()

    match selected_opt:
        case "s":
            break

        case "e":
            if raw_files:
                selected_files = raw_files
            else:
                print("Nenhum arquivo para encriptar.")
                continue

        case "d":
            if encrypted_files:
                selected_files = encrypted_files
            else:
                print("Nenhum arquivo para descriptografar.")
                continue

        case "es" | "ds":
            pass

        case _:
            print("Opcao invalida.")
            continue

    key_input = input("Digite uma chave de 8 caracteres: ")
    if len(key_input) != 8:
        print("A chave deve ter exatamente 8 caracteres")
        continue

    key = key_input.encode("utf-8")
    cipher = DES.new(key, DES.MODE_ECB)


    if selected_opt == "es":
        text = input("Digite a string para encriptar: ")
        data = text.encode("utf-8")

        encrypted_data = cipher.encrypt(pad(data, DES.block_size))
        print("String criptografada (hex):")
        print(encrypted_data.hex())

        continue

    if selected_opt == "ds":
        hex_input = input("Digite a string HEX para decriptar: ")

        data = bytes.fromhex(hex_input)
        decrypted_data = unpad(cipher.decrypt(data), DES.block_size)

        print("String descriptografada:")
        print("> " + decrypted_data.decode("utf-8"))

        continue

    print("----- Arquivos disponiveis: -----")
    for i, f in enumerate(selected_files):
        print(f"{i} - {f}")

    while True:
        num_file = int(input("Selecione o numero do arquivo: "))
        if 0 <= num_file < len(selected_files):
            selected_file = selected_files[num_file]
            break
        else:
            print("Numero invalido.")


    print(f"\nArquivo selecionado: {selected_file}")

    match selected_opt:
        case "e":
            with open(selected_file, "rb") as f:
                data = f.read()

            encrypted_data = cipher.encrypt(pad(data, DES.block_size))
            output_file = selected_file + encrypted_ext

            with open(output_file, "wb") as f:
                f.write(encrypted_data)

            print(f"Arquivo criptografado salvo em: {output_file}")

        case "d":
            with open(selected_file, "rb") as f:
                data = f.read()

            decrypted_data = unpad(cipher.decrypt(data), DES.block_size)

            dir_name = os.path.dirname(selected_file)
            file_name = os.path.basename(selected_file).replace(encrypted_ext, "")
            output_file = os.path.join(dir_name, "decrypted_" + file_name)

            with open(output_file, "wb") as f:
                f.write(decrypted_data)

            print(f"Arquivo descriptografado salvo em: {output_file}")