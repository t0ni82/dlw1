# ANSI Colores para terminal
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
BLUE = "\033[94m"

def text_to_ascii_bin(text):
    return [(c, ord(c), format(ord(c), '08b')) for c in text]

def xor_bin(b1, b2):
    return format(int(b1, 2) ^ int(b2, 2), '08b')

def bin_to_hex(b):
    return format(int(b, 2), '02X')

def ascii_bin_table(label, data, save=False):
    output = []
    output.append(f"{label}:\n")
    output.append(f"{'Letra':<6} {'ASCII':<6} {'Binario':<10}\n")
    output.append("-" * 24 + "\n")
    for letra, ascii_val, bin_val in data:
        output.append(f"{letra:<6} {ascii_val:<6} {bin_val:<10}\n")
    if not save:
        print(f"\n{CYAN}{label}:{RESET}")
        print(f"{CYAN}{'Letra':<6} {'ASCII':<6} {'Binario':<10}{RESET}")
        print(f"{CYAN}{'-' * 24}{RESET}")
        for letra, ascii_val, bin_val in data:
            print(f"{GREEN}{letra:<6}{RESET} {ascii_val:<6} {YELLOW}{bin_val:<10}{RESET}")
    return ''.join(output)

def xor_table(msg_bin, key_bin, save=False):
    output = []
    output.append(f"Resultado del XOR:\n")
    output.append(f"{'Mensaje':<10} {'Clave':<10} {'XOR':<10} {'Dec':<5} {'Hex':<5}\n")
    output.append("-" * 45 + "\n")
    xor_results = []
    for m, k in zip(msg_bin, key_bin):
        xor_res = xor_bin(m[2], k[2])
        dec = int(xor_res, 2)
        hex_val = bin_to_hex(xor_res)
        xor_results.append((xor_res, hex_val))
        output.append(f"{m[2]:<10} {k[2]:<10} {xor_res:<10} {dec:<5} {hex_val:<5}\n")
        if not save:
            print(f"{YELLOW}{m[2]:<10}{RESET} {YELLOW}{k[2]:<10}{RESET} {MAGENTA}{xor_res:<10}{RESET} {dec:<5} {MAGENTA}{hex_val:<5}{RESET}")
    return xor_results, ''.join(output)

def decrypt_table(cipher_bin, key_bin, save=False):
    output = []
    output.append(f"Descifrado:\n")
    output.append(f"{'Cifrado':<10} {'Clave':<10} {'XOR':<10} {'Dec':<5} {'Letra':<6}\n")
    output.append("-" * 48 + "\n")
    for c, k in zip(cipher_bin, key_bin):
        xor_res = xor_bin(c, k[2])
        letra = chr(int(xor_res, 2))
        dec = int(xor_res, 2)
        output.append(f"{c:<10} {k[2]:<10} {xor_res:<10} {dec:<5} {letra:<6}\n")
        if not save:
            print(f"{YELLOW}{c:<10}{RESET} {YELLOW}{k[2]:<10}{RESET} {MAGENTA}{xor_res:<10}{RESET} {dec:<5} {GREEN}{letra:<6}{RESET}")
    return ''.join(output)

def guardar_salida(texto):
    nombre = input("Nombre del archivo de salida (ej: resultado.txt): ").strip()
    if not nombre.endswith(".txt"):
        nombre += ".txt"
    try:
        with open(nombre, "w", encoding="utf-8") as f:
            f.write(texto)
        print(f"{BLUE}Salida guardada en '{nombre}'.{RESET}")
    except Exception as e:
        print(f"{RED}Error al guardar el archivo: {e}{RESET}")

def main():
    while True:
        print(f"\n{BLUE}--- Menú ---{RESET}")
        print("a) Cifrar un mensaje")
        print("b) Descifrar un mensaje")
        print("c) Salir")
        choice = input("Selecciona una opción: ").strip().lower()

        if choice == 'a':
            mensaje = input("Introduce el mensaje a cifrar: ").strip().upper()
            clave = input("Introduce la clave (misma longitud): ").strip().upper()
            if len(mensaje) != len(clave):
                print(f"{RED}Error: El mensaje y la clave deben tener la misma longitud.{RESET}")
                continue
            msg_data = text_to_ascii_bin(mensaje)
            key_data = text_to_ascii_bin(clave)

            texto = ""
            texto += ascii_bin_table("Mensaje", msg_data, save=True)
            ascii_bin_table("Mensaje", msg_data)
            texto += ascii_bin_table("Clave", key_data, save=True)
            ascii_bin_table("Clave", key_data)

            xor_result, xor_text = xor_table(msg_data, key_data, save=True)
            texto += xor_text
            hex_cifrado = [hex for _, hex in xor_result]
            cifrado_str = ' '.join(hex_cifrado)
            texto += f"\nMensaje cifrado (hex): {cifrado_str}\n"

            print(f"\n{CYAN}Mensaje cifrado (hex):{RESET} {cifrado_str}")

            if input("¿Deseas guardar la salida en un archivo de texto? (s/n): ").lower() == 's':
                guardar_salida(texto)

        elif choice == 'b':
            mensaje_hex = input("Introduce el mensaje cifrado (hex separado por espacios): ").strip().upper().split()
            clave = input("Introduce la clave (misma longitud): ").strip().upper()
            if len(mensaje_hex) != len(clave):
                print(f"{RED}Error: El mensaje cifrado y la clave deben tener la misma longitud.{RESET}")
                continue
            cipher_bin = [format(int(h, 16), '08b') for h in mensaje_hex]
            key_data = text_to_ascii_bin(clave)

            texto = ""
            texto += ascii_bin_table("Clave", key_data, save=True)
            ascii_bin_table("Clave", key_data)
            descifrado_txt = decrypt_table(cipher_bin, key_data, save=True)
            print()
            decrypt_table(cipher_bin, key_data)
            texto += descifrado_txt

            if input("¿Deseas guardar la salida en un archivo de texto? (s/n): ").lower() == 's':
                guardar_salida(texto)

        elif choice == 'c':
            print(f"{BLUE}Saliendo del programa.{RESET}")
            break
        else:
            print(f"{RED}Opción no válida. Inténtalo de nuevo.{RESET}")

if __name__ == '__main__':
    main()
