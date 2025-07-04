# Detección y Análisis de Vulnerabilidades de Software Instalado

Este proyecto permite identificar el software instalado en un sistema, buscar vulnerabilidades conocidas (CVEs) asociadas a dichos programas, y generar informes detallados con severidad CVSS y posibles exploits disponibles.

## 📁 Estructura del Proyecto

* `tfgLuis.py`: interfaz principal en línea de comandos para orquestar el proceso completo.
* `detectarSW.py`: detecta y filtra software instalado relevante según una lista de palabras clave.
* `limpiarSW.py`: refina la lista de software, eliminando paquetes irrelevantes o duplicados.
* `busquedaAPI_NVD_json.py`: consulta la API de NVD para obtener CVEs relacionados con el software detectado.
* `analizar_vulnerabilidades.py`: consolida los datos de vulnerabilidades y los cruza con la base de datos de Exploit-DB para detectar posibles exploits disponibles.

## 🧰 Requisitos

* Python 3.6 o superior
* Conexión a Internet
* Sistema operativo Linux o Windows

### 📦 Dependencias

Instalar con pip:

```bash
pip install requests tqdm
```

## ▶️ Uso

Ejecutar el script principal:

```bash
python3 tfgLuis.py
```

Pasos:

1. Escanear el sistema o cargar un archivo JSON.
2. Configurar la clave API de NVD.
3. Establecer el umbral de severidad CVSS.
4. Generar archivos `.json` y `.csv` con los resultados en `soluciones/`.

## 🔐 Clave API de NVD

Obtén tu clave gratuita en: [https://nvd.nist.gov/developers](https://nvd.nist.gov/developers)

Se guarda en `~/.cve_finder.cfg`.

## 📄 Archivos Generados

* `softwareTotal_<nombre>.json`: software detectado inicialmente.
* `softwareFiltrado_<nombre>.json`: software depurado.
* `vulnerabilidades_<nombre>.json` y `.csv`: resultados finales con CVEs y posibles exploits.

## ⚠️ Licencia

Este proyecto es de código abierto y de uso libre. Puede ser utilizado, modificado y distribuido por cualquier persona, sin restricciones.

---

# Installed Software Vulnerability Detection and Analysis

This project identifies installed software, searches for known vulnerabilities (CVEs), and generates detailed reports with CVSS severity and available exploits.

## 📁 Project Structure

* `tfgLuis.py`: main CLI script to orchestrate the full process.
* `detectarSW.py`: detects and filters relevant installed software.
* `limpiarSW.py`: refines the list by removing irrelevant/duplicate packages.
* `busquedaAPI_NVD_json.py`: queries the NVD API for related CVEs.
* `analizar_vulnerabilidades.py`: analyzes vulnerabilities and links to Exploit-DB.

## 🧰 Requirements

* Python 3.6+
* Internet connection
* Linux or Windows OS

### 📦 Dependencies

Install via pip:

```bash
pip install requests tqdm
```

## ▶️ Usage

Run the main script:

```bash
python3 tfgLuis.py
```

Steps:

1. Scan the system or load a JSON file.
2. Set your NVD API key.
3. Choose a CVSS severity threshold.
4. Get `.json` and `.csv` reports under `soluciones/`.

## 🔐 NVD API Key

Register and get your API key at: [https://nvd.nist.gov/developers](https://nvd.nist.gov/developers)

Stored at `~/.cve_finder.cfg`.

## 📄 Generated Files

* `softwareTotal_<name>.json`: initial detected software list.
* `softwareFiltrado_<name>.json`: cleaned list.
* `vulnerabilidades_<name>.json` and `.csv`: final CVE report with possible exploits.

## ⚠️ License

This project is open-source and free to use. Anyone can use, modify, and distribute it without restriction.
