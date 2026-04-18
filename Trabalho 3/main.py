from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key( 
    public_exponent=65537, # Unless you have a specific reason to do otherwise, you should always use 65537 -> recomendado pela biblioteca
    key_size=4096
)

public_key = private_key.public_key()

message = input("Mensagem: ").encode() # str -> bytes

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(  # OAEP: esquema de padding seguro para RSA que
                   # - adiciona aleatoriedade à mensagem (evita resultados determinísticos)
                   # - aplica funções de hash (SHA-256) para "embaralhar" os dados
                   # - utiliza MGF1 para gerar máscaras pseudoaleatórias
                   # - produz um bloco estruturado e reversível, protegendo contra ataques criptográficos
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nMensagem criptografada:")
print(ciphertext)

decrypted_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nMensagem descriptografada:")
print(decrypted_message.decode()) # bytes -> str
