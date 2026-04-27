import os
from aux import *
from send import *
from receive import *

# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()
# key = hashlib.sha256(b"AAAAAAAAAAAAAAAAAAAAA").digest()
# salt = "BBBBBBBBBBBBBBB"

if __name__ == "__main__":
    import sys

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    send_algorithms = {
        "1": ("exercicio1_send (confidencialidade + integridade)", exercicio1_send),
        "2": ("exercicio2_send (integridade)", exercicio2_send),
        "3": ("exercicio3_send (autenticidade + integridade)", exercicio3_send),
        "4": ("exercicio4_send (confidencialidade + autenticidade + integridade)", exercicio4_send),
        "5": ("exercicio5_send (integridade com hash + salt)", exercicio5_send),
        "6": ("exercicio6_send (confidencialidade + integridade com salt)", exercicio6_send),
    }

    receive_algorithms = {
        "1": ("exercicio1_receive", exercicio1_receive),
        "2": ("exercicio2_receive", exercicio2_receive),
        "3": ("exercicio3_receive", exercicio3_receive),
        "4": ("exercicio4_receive", exercicio4_receive),
        "5": ("exercicio5_receive", exercicio5_receive),
        "6": ("exercicio6_receive", exercicio5_receive),
    }

    while True:
        clear()
        print("=== MENU ===")
        print("1 - Enviar (criptografar)")
        print("2 - Receber (descriptografar)")
        print("0 - Sair")

        option = input("\nEscolha uma opção: ").strip()

        if option == "0":
            clear()
            print("Saindo...")
            sys.exit(0)

        clear()

        # listar arquivos
        files = [f for f in os.listdir(".") if os.path.isfile(f)]

        if not files:
            print("Nenhum arquivo encontrado no diretório.")
            input("\nPressione ENTER para continuar...")
            continue

        print("Arquivos disponíveis:\n")
        for i, f in enumerate(files):
            print(f"{i} - {f}")

        try:
            file_index = int(input("\nSelecione o arquivo: "))
            selected_file = files[file_index]
        except (ValueError, IndexError):
            print("Seleção inválida.")
            input("\nPressione ENTER para continuar...")
            continue

        clear()

        if option == "1":
            print("Algoritmos disponíveis (send):\n")
            for k, v in send_algorithms.items():
                print(f"{k} - {v[0]}")

            alg_option = input("\nEscolha o algoritmo: ").strip()

            if alg_option not in send_algorithms:
                print("Algoritmo inválido.")
                input("\nPressione ENTER para continuar...")
                continue

            func = send_algorithms[alg_option][1]

            try:
                output = func(selected_file, key)
                print(f"\nArquivo criptografado gerado:\n{output}")
            except Exception as e:
                print(f"\nErro: {e}")

        elif option == "2":
            print("Algoritmos disponíveis (receive):\n")
            for k, v in receive_algorithms.items():
                print(f"{k} - {v[0]}")

            alg_option = input("\nEscolha o algoritmo: ").strip()

            if alg_option not in receive_algorithms:
                print("Algoritmo inválido.")
                input("\nPressione ENTER para continuar...")
                continue

            func = receive_algorithms[alg_option][1]

            try:
                output = func(selected_file, key)
                print(f"\nArquivo recuperado:\n{output}")
            except Exception as e:
                print(f"\nErro: {e}")

        else:
            print("Opção inválida.")

        input("\nPressione ENTER para voltar ao menu...")