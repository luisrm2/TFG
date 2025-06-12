# tfgLuis.py
import os
import platform
import subprocess
import sys

ENTRADA_JSON_PRUEBA = "software_Prueba.json"
CONFIG_FILE = os.path.expanduser("~/.cve_finder.cfg")
SOLUCIONES_DIR = "soluciones"

usar_log = False
nombre_prueba = ""

def log(msg):
    if usar_log:
        with open(f"logFile_{nombre_prueba}.log", "a") as f:
            f.write(msg + "\n")
    else:
        print(msg)

def detectar_sistemaPretty():
    log("Detectando sistema operativo...")
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME"):
                    log(f"Sistema detectado: {line.strip().split('=')[1].strip(' \"')}")
                    return
    except:
        log(f"Sistema detectado: {platform.system()} {platform.release()}")

def menu():
    global usar_log
    print("\n¿Qué deseas hacer?")
    print("1. Escanear software instalado")
    print("2. Cargar archivo JSON externo")
    print("3. Usar archivo de prueba")
    print("4. Configurar clave API de NVD")
    eleccion = input("Selecciona opción (1/2/3/4): ").strip()
    if eleccion == "4":
        clave = input("Introduce tu clave API de NVD: ").strip()
        if clave:
            with open(CONFIG_FILE, 'w') as f:
                f.write(clave)
            print(f"Clave API guardada en {CONFIG_FILE}")
        sys.exit(0)

    print("\n¿Deseas registrar los resultados en un archivo de log? (s/n):")
    usar_log = input().strip().lower() == 's'

    if eleccion == "1":
        subprocess.run(["python3", "src/detectarSW.py", nombre_prueba])
        ruta_filtrado = os.path.join("softwares", f"softwareFiltrado_{nombre_prueba}.json")

        try:
            max_softwares = int(input("\n¿Cuántos softwares quieres analizar como máximo? (Deja en blanco para todos): ") or 0)
        except ValueError:
            max_softwares = 0

        return ruta_filtrado, max_softwares

    elif eleccion == "2":
        ruta = input("Ruta al archivo JSON: ").strip()
        if os.path.exists(ruta):
            return ruta
        else:
            print("Archivo no encontrado. Saliendo...")
            sys.exit(1)
    elif eleccion == "3":
        return os.path.join("softwares", ENTRADA_JSON_PRUEBA)

    else:
        print("Opción inválida. Saliendo...")
        sys.exit(1)

def main():
    global nombre_prueba
    nombre_prueba = input("\nNombre para los archivos de solución (sin extensión): ").strip()
    if not nombre_prueba:
        print("Nombre no válido. Saliendo...")
        sys.exit(1)

    detectar_sistemaPretty()
    resultado_menu = menu()
    if isinstance(resultado_menu, tuple):
        ruta_entrada, max_softwares = resultado_menu
    else:
        ruta_entrada = resultado_menu
        max_softwares = 0

    try:
        threshold = float(input("\nUmbral mínimo de severidad CVSS (0.0 - 10.0, default 9.0): ") or 9.0)
    except ValueError:
        threshold = 9.0

    os.makedirs(SOLUCIONES_DIR, exist_ok=True)
    json_path = os.path.join(SOLUCIONES_DIR, f"vulnerabilidades_{nombre_prueba}.json")
    csv_path = os.path.join(SOLUCIONES_DIR, f"vulnerabilidades_{nombre_prueba}.csv")
    log_file = os.path.join(SOLUCIONES_DIR, f"logFile_{nombre_prueba}.log")

    comando = [
    "python3", "src/analizar_vulnerabilidades.py",
    "--input", ruta_entrada,    
    "--threshold", str(threshold),
    "--json", json_path,
    "--csv", csv_path,
    "--logfile", log_file,
    
    ]
    if max_softwares > 0:
        comando += ["--limit", str(max_softwares)]

    subprocess.run(comando)

if __name__ == "__main__":
    main()
