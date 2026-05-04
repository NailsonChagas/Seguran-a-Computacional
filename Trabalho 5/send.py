# send.py
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import base64
import json

def generate_dsa_keys():
    key = DSA.generate(2048)
    
    with open('sender_private_key.pem', 'wb') as f:
        f.write(key.export_key('PEM'))
    
    with open('sender_public_key.pem', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))
    
    return key

def sign_file(input_file, private_key):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    hash_obj = SHA256.new(data)
    signer = DSS.new(private_key, 'fips-186-3') # fips-186-3 Usa valor k aleatório a cada assinatura
    signature = signer.sign(hash_obj)
    
    return signature, data

def encrypt_aes(data, password):
    iv = get_random_bytes(16)
    
    # Derivação de chave simples sem salt
    from Crypto.Protocol.KDF import PBKDF2
    key = PBKDF2(password, b'', dkLen=32, count=100000)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Padding PKCS7
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    
    ciphertext = cipher.encrypt(padded_data)
    
    # Formato: iv(16) + ciphertext
    return iv + ciphertext

def list_available_files():
    print("\n=== ARQUIVOS DISPONÍVEIS ===")
    files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.endswith('.pem') and not f.endswith('.json')]
    
    if not files:
        print("Nenhum arquivo encontrado no diretório atual!")
        return []
    
    for i, file in enumerate(files, 1):
        size = os.path.getsize(file)
        print(f"{i}. {file} ({size} bytes)")
    
    print(f"{len(files)+1}. Digitar nome do arquivo manualmente")
    return files

def select_file():
    files = list_available_files()
    
    if not files:
        return input("\nDigite o caminho completo do arquivo: ").strip()
    
    try:
        choice = input(f"\nSelecione uma opção (1-{len(files)+1}): ").strip()
        choice_num = int(choice)
        
        if 1 <= choice_num <= len(files):
            return files[choice_num - 1]
        elif choice_num == len(files) + 1:
            return input("Digite o nome do arquivo: ").strip()
        else:
            print("[!] Opção inválida! Usando entrada manual...")
            return input("Digite o nome do arquivo: ").strip()
    except ValueError:
        print("[!] Entrada inválida! Usando entrada manual...")
        return input("Digite o nome do arquivo: ").strip()

def main():
    print("=== SENDER - Geração e Envio de Mensagem Assinada ===\n")
    
    # 1. Gerar chaves (ou carregar existentes)
    if not (os.path.exists('sender_private_key.pem') and 
            os.path.exists('sender_public_key.pem')):
        private_key = generate_dsa_keys()
    else:
        with open('sender_private_key.pem', 'rb') as f:
            private_key = DSA.import_key(f.read())
        print("[✓] Chave privada carregada")
    
    # 2. Selecionar arquivo com listagem
    input_file = select_file()
    
    if not input_file or not os.path.exists(input_file):
        print("[-] Arquivo não encontrado!")
        return
    
    print(f"\n[✓] Arquivo selecionado: {input_file}")
    
    # 3. Assinar
    signature, data = sign_file(input_file, private_key)
    signature_b64 = base64.b64encode(signature).decode('ascii')
    print(f"[✓] Arquivo assinado (assinatura: {len(signature)} bytes)")
    
    # 4. Escolher se deseja cifrar ou não
    encrypt_option = input("\nCifrar arquivo? (s/n): ").lower()
    
    if encrypt_option == 's':
        password = input("Senha para cifragem: ")
        encrypted_data = encrypt_aes(data, password)
        data_to_send = encrypted_data
        mode = "encrypted"
    else:
        data_to_send = data
        mode = "plain_text"
    
    # 5. Salvar pacote para envio
    package = {
        'mode': mode,
        'signature': signature_b64,
        'data': base64.b64encode(data_to_send).decode('ascii'),
        'original_filename': input_file
    }
    
    with open('send_package.json', 'w') as f:
        json.dump(package, f, indent=4, sort_keys=False)
    
    print(f"\n[✓] Pacote criado: send_package.json")
    print(f"[✓] Modo: {mode}")
    print(f"[✓] Arquivo original: {input_file}")
    print("\n=== ARQUIVOS PARA ENVIAR AO DESTINATÁRIO ===")
    print("1. send_package.json (mensagem + assinatura)")
    print("2. sender_public_key.pem (chave pública)")

if __name__ == "__main__":
    main()