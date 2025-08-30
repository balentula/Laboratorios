#!/usr/bin/env python3
import sys
import time
import random
from scapy.all import IP, ICMP, send

def generar_relleno(longitud):

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
    destino = "8.8.8.8"
    identificador_base = 0x1234
    seq_number = 1

    for i, char in enumerate(mensaje):

        char_data = char.encode("utf-8")
        restante = 48 - len(char_data)
        extra_payload = generar_relleno(restante)
        payload = char_data + extra_payload
        pkt = IP(dst=destino) / ICMP(id=identificador_base + i, seq=seq_number) / payload

        print("Sent 1 packets.")

        send(pkt, verbose=0)

        seq_number += 1
        time.sleep(0.1)

if __name__ == "__main__":
    main()
