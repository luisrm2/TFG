# analizar_vulnerabilidades.py
import os
import platform
import subprocess
import json
import time
import sys
import re
from tqdm import tqdm
import csv
from io import StringIO
import requests
import argparse
from limpiarSW import limpiar_version

ENTRADA_JSON_PRUEBA = "software_Prueba.json"
CONFIG_FILE = os.path.expanduser("~/.cve_finder.cfg")

NORMALIZACIONES = {
    "apache2": "apache",
    "python3": "python",
    "openjdk-17": "openjdk",
    "openjdk-11": "openjdk",
    "nodejs": "node",
    "mysql-server": "mysql",
    "libreoffice-core": "libreoffice",
    "postgresql-13": "postgresql",
    "nginx-core": "nginx",
    "php-cli": "php",
    "php8.1": "php",
    "php": "php",
    "vsftpd": "ftp",
    "wireshark-common": "wireshark",
    "ruby3.3": "ruby",
    "ruby3.2": "ruby",
    "ruby3.1": "ruby",
    "sqlite3": "sqlite",
    "openssh-client": "openssh"
}

def normalizar_nombre(nombre):
    return NORMALIZACIONES.get(nombre.lower(), nombre)

def guardar_resultados(datos, json_out, csv_out):
    with open(json_out, "w") as f:
        json.dump(datos, f, indent=2)
    with open(csv_out, "w") as f:
        f.write("Software,CVE ID,CVSS Score,Descripcion,Exploit,Exploit Descripcion\n")
        for d in datos:
            f.write(f'{d["Software"]},{d["CVE ID"]},{d["CVSS Score"]},"{d["Descripcion"].replace(",", " ")}",{d.get("Exploit", "")},"{d.get("Exploit Descripcion", "").replace(",", " ")}"\n')
        
    print(f"Archivos generados: {json_out}, {csv_out}")

exploit_db_cache = None
def get_exploit_db():
    global exploit_db_cache
    if exploit_db_cache is not None:
        return exploit_db_cache

    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"
    try:
        response = requests.get(url)
        response.raise_for_status()
        csv_content = StringIO(response.text)
        reader = csv.DictReader(csv_content)
        exploit_db_cache = {row['id']: row for row in reader}
        return exploit_db_cache
    except Exception as e:
        print(f"Error al obtener Exploit-DB: {e}")
        return {}

def search_exploitdb(cve_id):
    exploits = []
    cve_id = cve_id.lower()
    exploit_db = get_exploit_db()

    for exp_id, data in exploit_db.items():
        if cve_id in data.get('codes', '').lower():
            exploits.append({
                'id': exp_id,
                'description': data['description'],
                'link': f"https://www.exploit-db.com/exploits/{exp_id}"
            })
    return exploits

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="Ruta al JSON de entrada")
    parser.add_argument("--threshold", type=float, default=9.0, help="Umbral mínimo de CVSS")
    parser.add_argument("--json", help="Ruta de salida JSON")
    parser.add_argument("--csv", help="Ruta de salida CSV")
    parser.add_argument("--logfile", help="Archivo para registrar peticiones a NVD")
    parser.add_argument("--limit", type=int, help="Máximo número de softwares a analizar")
    parser.add_argument("--component", help="Nombre del software a consultar individualmente")
    parser.add_argument("--version", help="Versión del software a consultar individualmente")
    parser.add_argument("--stdout", action="store_true", help="Imprimir resultados en consola en lugar de guardar archivos")

    args = parser.parse_args()

    if not args.stdout and (not args.json or not args.csv):
        print("Debes proporcionar --json y --csv, o usar --stdout para imprimir por consola.")
        sys.exit(1)

    if args.component and args.version:
        software = [{"name": args.component, "version": args.version}]
    elif args.input:
        with open(args.input) as f:
            software = json.load(f)
        if args.limit:
            software = software[:args.limit]
    else:
        print("Error: Debes proporcionar --component y --version, o bien --input con un archivo JSON.")
        sys.exit(1)

    def registrar_peticion(texto):
        if args.logfile:
            with open(args.logfile, "a") as f:
                f.write(texto + "\n")

    def ejecutar_busqueda(componente, version, threshold):
        registrar_peticion(f"[QUERY] Buscando: {componente} {version} (CVSS ≥ {threshold})")
        try:
            resultado = subprocess.run([
                "python3", "src/busquedaAPI_NVD_json.py",
                "-c", componente, "-v", version,
                "--jsonOutput", "--cvssMin", str(threshold)
            ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            return json.loads(resultado.stdout)
        except Exception as e:
            registrar_peticion(f"[ERROR] Fallo en busqueda de {componente} {version}: {e}")
            return []

    resultados = []
    for sw in tqdm(software, desc="Buscando vulnerabilidades", unit="soft"):
        original = sw["name"]
        nombre = normalizar_nombre(original)
        version = limpiar_version(sw["version"])
        cves = ejecutar_busqueda(nombre, version, args.threshold)
        for cve in cves:
            cve["Software"] = original
            exploits = search_exploitdb(cve["CVE ID"])
            if exploits:
                cve["Exploit"] = exploits[0]["link"]
                cve["Exploit Descripcion"] = exploits[0]["description"]
            else:
                cve["Exploit"] = ""
                cve["Exploit Descripcion"] = ""
            resultados.append(cve)

        time.sleep(1.5)

    if args.stdout:
        print(json.dumps(resultados, indent=2))
    else:
        guardar_resultados(resultados, args.json, args.csv)



if __name__ == "__main__":
    main()
