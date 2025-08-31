
import sys
from scapy.all import rdpcap, ICMP, Raw
from termcolor import colored

def cesar_decode(texto, shift):
    out = []
    for c in texto:
        if 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        elif 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)

def calcular_probabilidad(mensaje):
    comunes = [" el ", " la ", " de ", " que ", " en ", " un ", " es ", " y ", " the ", " and ", " to "]
    m = " " + mensaje.lower() + " "
    score = sum(2 for w in comunes if w in m)
    legibles = sum(1 for c in mensaje if 32 <= ord(c) <= 126)
    score += legibles / max(1, len(mensaje))
    return score

def leer_mensaje_archivo(nombre_archivo):
    paquetes = rdpcap(nombre_archivo)

    vistos = set()
    chars = []

    for p in paquetes:
        if p.haslayer(ICMP):
            icmp = p[ICMP]
            if getattr(icmp, "type", None) == 8:
                key = (getattr(icmp, "id", None), getattr(icmp, "seq", None))
                if key in vistos:
                    continue
                vistos.add(key)

                raw_bytes = bytes(p[Raw].load) if p.haslayer(Raw) else bytes(icmp.payload)
                if raw_bytes and len(raw_bytes) >= 1:
                    chars.append(chr(raw_bytes[0]))

    return "".join(chars)

def main():
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <archivo.pcapng>")
        sys.exit(1)

    archivo = sys.argv[1]
    mensaje_bruto = leer_mensaje_archivo(archivo)

    candidatos = []
    for shift in range(26):
        cand = cesar_decode(mensaje_bruto, shift)
        score = calcular_probabilidad(cand)
        candidatos.append((shift, cand, score))

    mejor_shift, mejor_texto, _ = max(candidatos, key=lambda x: x[2])

    for shift, cand, _ in candidatos:
        linea = f"{shift}  {cand}"
        if shift == mejor_shift:
            print(colored(linea, "green"))
        else:
            print(linea)

if __name__ == "__main__":
    main()
