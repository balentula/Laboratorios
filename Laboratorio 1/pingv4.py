#!/usr/bin/env python3
import sys
import time
import random
from scapy.all import IP, ICMP, send

def generar_relleno(longitud):
    """Genera relleno con 0x00 + símbolos + números, sin letras"""
    simbolos = [ord(c) for c in "$%&#"]
    numeros = [ord(c) for c in "0123456789"]

    relleno = []
    for _ in range(longitud):
        tipo = random.choice(["zero", "symbol", "number"])
        if tipo == "zero":
            relleno.append(0x00)
        elif tipo == "symbol":
            relleno.append(random.choice(simbolos))
        else:
            relleno.append(random.choice(numeros))
    return bytes(relleno)

def main():
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} \"<string>\"")
        sys.exit(1)

    mensaje = sys.argv[1]
    destino = "8.8.8.8"   # Cambia la IP destino si lo necesitas
    identificador_base = 0x1234
    seq_number = 1

    for i, char in enumerate(mensaje):
        # Primer byte = carácter del mensaje
        char_data = char.encode("utf-8")

        # Generar relleno hasta completar 48 bytes
        restante = 48 - len(char_data)
        extra_payload = generar_relleno(restante)

        # Payload final
        payload = char_data + extra_payload

        # Construcción del paquete ICMP
        pkt = IP(dst=destino) / ICMP(id=identificador_base + i, seq=seq_number) / payload

        print(f"Enviando '{char}' -> destino {destino} "
              f"(ID={identificador_base+i}, Seq={seq_number}, Data={len(payload)} bytes)")

        send(pkt, verbose=0)

        seq_number += 1
        time.sleep(0.1)

if __name__ == "__main__":
    main()
