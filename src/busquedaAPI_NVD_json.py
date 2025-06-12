#busquedaAPI_NVD_json.py
import sys
import os
import requests
import json
import argparse

CONFIG_FILE = os.path.expanduser("~/.cve_finder.cfg")

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return f.read().strip()
    return None

def save_api_key(api_key):
    with open(CONFIG_FILE, 'w') as f:
        f.write(api_key)
    print(f"API key guardada en {CONFIG_FILE}")

def parse_args():
    parser = argparse.ArgumentParser(description="Modo JSON de busquedaAPI_NVD para integración automática.")
    parser.add_argument("-c", "--component", required=True, help="Nombre del componente (ej: Apache)")
    parser.add_argument("-v", "--version", required=True, help="Versión del componente")
    parser.add_argument("--apiStore", help="Guardar clave API para uso futuro")
    parser.add_argument("--jsonOutput", action="store_true", help="Devolver resultados como JSON")
    parser.add_argument("--cvssMin", type=float, default=0.0, help="Puntuación mínima CVSS para filtrar (ej. 7.0)")
    return parser.parse_args()

def buscar_cves_criticos(componente, version, cvss_min=9.0):
    api_key = load_api_key()
    bruto = query_nvd(componente, version, api_key=api_key)
    if "error" in bruto:
        return []
    return filtrar_criticos(bruto, cvss_min)

def query_nvd(component, version, api_key=None):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{component} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 1000}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"HTTP {response.status_code}",
                "code": response.status_code,
                "component": component,
                "version": version
            }
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "code": -1,
            "component": component,
            "version": version
        }


def filtrar_criticos(data, umbral):
    criticos = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        id_cve = cve.get("id", "UNKNOWN")
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        score = 0.0
        if "metrics" in cve:
            for metric in cve["metrics"].values():
                for vector in metric:
                    score = max(score, vector.get("cvssData", {}).get("baseScore", 0.0))
        if score >= umbral:
            criticos.append({
                "CVE ID": id_cve,
                "CVSS Score": score,
                "Descripcion": desc
            })
    return criticos

def main():
    args = parse_args()

    if args.apiStore:
        save_api_key(args.apiStore)
        sys.exit(0)

    api_key = load_api_key()
    bruto = query_nvd(args.component, args.version, api_key=api_key)

    if "error" in bruto:
        error_msg = f"[ERROR] Código de retorno {bruto['code']} para {bruto['component']} {bruto['version']}: {bruto['error']}"
        print(error_msg)
        sys.exit(1)

    if args.jsonOutput:
        resultado = filtrar_criticos(bruto, args.cvssMin)
        print(json.dumps(resultado, indent=2))
    else:
        print("Use --jsonOutput para devolver resultados estructurados.")


if __name__ == "__main__":
    main()

