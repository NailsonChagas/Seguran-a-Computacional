# receive.py - Recebe e processa o pacote enviado
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import base64
import json

def decrypt_aes(encrypted_data, password):
    # Extrai iv (16) e ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Deriva a chave usando a mesma senha (sem salt)
    key = PBKDF2(password, b'', dkLen=32, count=100000)
    
    # Decifra
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # Remove padding PKCS7
    padding_len = decrypted_padded[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Padding inválido")
    
    decrypted_data = decrypted_padded[:-padding_len]
    return decrypted_data

def verify_signature(data, signature, public_key):
    try:
        hash_obj = SHA256.new(data)
        verifier = DSS.new(public_key, 'fips-186-3')
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def save_received_file(data, original_filename):
    # Adiciona prefixo 'received_' para não sobrescrever
    base_name = os.path.basename(original_filename)
    name, ext = os.path.splitext(base_name)
    received_filename = f"received_{name}{ext}"
    
    # Se já existir, adiciona número
    counter = 1
    while os.path.exists(received_filename):
        received_filename = f"received_{name}_{counter}{ext}"
        counter += 1
    
    with open(received_filename, 'wb') as f:
        f.write(data)
    
    return received_filename

def verify_package_structure(package):
    required_fields = ['mode', 'signature', 'data', 'original_filename']
    
    for field in required_fields:
        if field not in package:
            print(f"[-] Erro: Campo '{field}' não encontrado no pacote!")
            return False
    
    return True

def main():
    print("=== RECEIVER - Recebimento e Verificação de Mensagem ===\n")
    
    # 1. Verificar se o arquivo do pacote existe
    if not os.path.exists('send_package.json'):
        print("[-] Erro: Arquivo 'send_package.json' não encontrado!")
        print("    Certifique-se que o arquivo está no diretório atual.")
        return
    
    # 2. Carregar o pacote
    try:
        with open('send_package.json', 'r') as f:
            package = json.load(f)
        print("[✓] Pacote carregado com sucesso")
    except json.JSONDecodeError:
        print("[-] Erro: Arquivo 'send_package.json' está corrompido ou não é JSON válido!")
        return
    except Exception as e:
        print(f"[-] Erro ao carregar pacote: {e}")
        return
    
    # 3. Verificar estrutura do pacote
    if not verify_package_structure(package):
        return
    
    mode = package['mode']
    signature_b64 = package['signature']
    data_b64 = package['data']
    original_filename = package['original_filename']
    
    print(f"[✓] Modo do pacote: {mode}")
    print(f"[✓] Arquivo original: {original_filename}")
    
    # 4. Carregar chave pública do remetente
    if not os.path.exists('sender_public_key.pem'):
        print("[-] Erro: Arquivo 'sender_public_key.pem' não encontrado!")
        print("    É necessário ter a chave pública do remetente para verificar a assinatura.")
        return
    
    try:
        with open('sender_public_key.pem', 'rb') as f:
            public_key = DSA.import_key(f.read())
        print("[✓] Chave pública do remetente carregada")
    except Exception as e:
        print(f"[-] Erro ao carregar chave pública: {e}")
        return
    
    # 5. Decodificar dados
    try:
        signature = base64.b64decode(signature_b64)
        encrypted_data = base64.b64decode(data_b64)
        print(f"[✓] Dados decodificados (tamanho: {len(encrypted_data)} bytes)")
    except Exception as e:
        print(f"[-] Erro ao decodificar dados: {e}")
        return
    
    # 6. Se estiver cifrado, solicitar senha e decifrar
    if mode == "encrypted":
        print("\n[!] O pacote está cifrado!")
        password = input("Digite a senha para decifrar: ")
        
        try:
            data = decrypt_aes(encrypted_data, password)
            print(f"[✓] Dados decifrados com sucesso (tamanho: {len(data)} bytes)")
        except Exception as e:
            print(f"[-] Erro ao decifrar dados: {e}")
            print("    Senha incorreta ou dados corrompidos!")
            return
    elif mode == "plain_text":
        data = encrypted_data
        print("[✓] Pacote não cifrado")
    else:
        print(f"[-] Modo desconhecido: {mode}")
        return
    
    # 7. Verificar assinatura
    print("\n=== VERIFICANDO ASSINATURA ===")
    is_valid = verify_signature(data, signature, public_key)
    
    if is_valid:
        print("[✓] ASSINATURA VÁLIDA!")
        print("    A mensagem é autêntica e não foi alterada.")
        
        # 8. Salvar o arquivo recebido
        saved_file = save_received_file(data, original_filename)
        print(f"\n[✓] Arquivo salvo como: {saved_file}")
        
        # Exibir informações do arquivo
        file_size = os.path.getsize(saved_file)
        print(f"    Tamanho: {file_size} bytes")
        
    else:
        print("[-] ASSINATURA INVÁLIDA!")
        print("    A mensagem pode ter sido alterada ou não é autêntica!")
        print("    NÃO confie neste arquivo!")
    
    # 9. Resumo da verificação
    print("\n=== RESUMO DA VERIFICAÇÃO ===")
    print(f"Arquivo original: {original_filename}")
    print(f"Modo: {mode}")
    print(f"Assinatura: {'VÁLIDA' if is_valid else 'INVÁLIDA'}")
    print(f"Autenticidade: {'CONFIRMADA' if is_valid else 'NÃO CONFIRMADA'}")
    
    if is_valid and mode == "encrypted":
        print("Integridade: CONFIRMADA")
        print("Confidencialidade: PRESERVADA (dados cifrados)")

if __name__ == "__main__":
    main()