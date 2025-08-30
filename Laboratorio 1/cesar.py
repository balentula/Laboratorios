import sys

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

def cifrado_cesar(texto, desplazamiento=3):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = 'A' if caracter.isupper() else 'a'
            indice_base = ord(base)
            resultado += chr((ord(caracter) - indice_base + desplazamiento) % 26 + indice_base)
        else:
            resultado += caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: sudo python3 cesar.py \"texto_a_cifrar\" N")
        sys.exit(1)

    texto = sys.argv[1]
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("El segundo argumento debe ser un número entero (desplazamiento).")
        sys.exit(1)

    cifrado = cifrado_cesar(texto, desplazamiento)
    print(cifrado)