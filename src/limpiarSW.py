# limpiarSW.py
import json
import sys
import re

IGNORAR_PATRONES = [
    "lib", "common", "data", "doc", "utils", "core", "fonts", "dev",
    "gtk", "xfce", "gnome", "mate", "theme", "icon", "locale", "dbg"
]

def limpiar_software(nombre_base):
    entrada = f"softwares/softwareTotal_{nombre_base}.json"
    salida = f"softwares/softwareFiltrado_{nombre_base}.json"
    try:
        with open(entrada, "r") as f:
            paquetes = json.load(f)
    except Exception as e:
        print(f"Error leyendo archivo: {e}")
        return

    filtrado = []
    ya_incluidos = set()
    for item in paquetes:
        nombre = item["name"].lower()
        if any(pat in nombre for pat in IGNORAR_PATRONES):
            continue
        base = nombre.split("-")[0]
        if base not in ya_incluidos:
            filtrado.append(item)
            ya_incluidos.add(base)

    try:
        with open(salida, "w") as f:
            json.dump(filtrado, f, indent=2)
        print(f"Archivo filtrado guardado en {salida} con {len(filtrado)} elementos.")
    except Exception as e:
        print(f"Error escribiendo archivo: {e}")

def limpiar_version(version):
    return re.split(r'[-+]', version)[0]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Debes proporcionar el nombre base.")
        sys.exit(1)
    limpiar_software(sys.argv[1])
