#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, ICMP
from termcolor import colored

def cesar_decode(texto, shift):
    """Decodifica un string aplicando corrimiento tipo César"""
    resultado = ""
    for c in texto:
        if 'A' <= c <= 'Z':
            resultado += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        elif 'a' <= c <= 'z':
            resultado += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        else:
            resultado += c
    return resultado

def calcular_probabilidad(mensaje):
    """Evalúa qué tan 'legible' es un mensaje (heurística simple)"""
    comunes = ["el", "la", "de", "que", "en", "un", "es", "y", "the", "and", "to"]
    score = 0
    for palabra in comunes:
        if palabra in mensaje.lower():
            score += 2
    # puntaje extra por proporción de caracteres imprimibles
    legibles = sum(1 for c in mensaje if 32 <= ord(c) <= 126)
    score += legibles / max(1, len(mensaje))
    return score

def leer_mensaje_archivo(nombre_archivo):
    """Lee un archivo .pcapng y extrae el mensaje transmitido en ICMP"""
    print(f"[+] Leyendo archivo {nombre_archivo} ...")
    paquetes = rdpcap(nombre_archivo)

    mensaje_bruto = ""
    for p in paquetes:
        if p.haslayer(ICMP) and hasattr(p[ICMP], "payload"):
            raw = bytes(p[ICMP].payload)
            if len(raw) >= 1:
                mensaje_bruto += chr(raw[0])  # primer byte = letra transmitida
    return mensaje_bruto

def main():
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <archivo.pcapng>")
        sys.exit(1)

    archivo = sys.argv[1]

    # Leer mensaje bruto desde el archivo
    mensaje_bruto = leer_mensaje_archivo(archivo)
    print(f"[+] Mensaje bruto capturado: {mensaje_bruto}")

    # Probar todas las combinaciones posibles (corrimientos César)
    mejores = []
    for shift in range(26):
        candidato = cesar_decode(mensaje_bruto, shift)
        score = calcular_probabilidad(candidato)
        mejores.append((candidato, score, shift))

    # Ordenar por puntaje
    mejores.sort(key=lambda x: x[1], reverse=True)

    print("\nPosibles decodificaciones:")
    for i, (cand, score, shift) in enumerate(mejores):
        if i == 0:
            print(colored(f"[Shift={shift}] {cand}", "green"))  # mejor opción
        else:
            print(f"[Shift={shift}] {cand}")

if __name__ == "__main__":
    main()
