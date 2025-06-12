# detectarSW.py
import subprocess
import json
import os
import sys
import platform

KEYWORDS = [
    "apache", "nginx", "lighttpd", "caddy", "varnish", "squid",
    "mysql", "mariadb", "postgresql", "mongodb", "redis", "sqlite",
    "python", "perl", "php", "ruby", "nodejs", "openjdk", "java", "go", "rust", "dotnet", "mono",
    "docker", "podman", "lxc", "qemu", "kvm", "virtualbox", "vmware", "libvirt", "vagrant",
    "wireshark", "nmap", "snort", "clamav", "lynis", "fail2ban", "rkhunter", "chkrootkit", "openvas", "tripwire",
    "openssh", "openvpn", "strongswan", "ipsec", "netcat", "iperf", "tcpdump", "net-tools", "ethtool", "iftop",
    "postfix", "dovecot", "exim", "sendmail", "bind9", "dnsmasq", "spamassassin", "mailutils",
    "vsftpd", "proftpd", "pure-ftpd", "samba",
    "gnome", "kde", "xfce", "lxde", "mate", "cinnamon", "fluxbox", "openbox",
    "vim", "emacs", "nano", "gedit", "kate", "geany", "code", "sublime-text", "atom", "eclipse", "intellij",
    "libreoffice", "openoffice", "gimp", "inkscape", "blender", "vlc", "audacity", "kdenlive", "obs-studio",
    "rsync", "duplicity", "borgbackup", "restic", "syncthing", "nextcloud", "owncloud",
    "cups", "cron", "systemd", "logrotate", "ufw", "firewalld", "iptables", "nfs-kernel-server", "apache2-utils"
]

import shutil

def detectar_sistema():
    sistema = platform.system().lower()
    if sistema == "windows":
        return "windows"
    elif sistema == "linux":
        if shutil.which("dpkg"):
            return "debian"
        elif shutil.which("rpm"):
            return "redhat"
        else:
            return "linux"
    else:
        return "otro"


def obtener_paquetes_dpkg():
    try:
        resultado = subprocess.run(['dpkg', '-l'], stdout=subprocess.PIPE, text=True)
        return resultado.stdout.splitlines()
    except Exception as e:
        print(f"Error al ejecutar dpkg -l: {e}")
        return []

def obtener_paquetes_rpm():
    try:
        resultado = subprocess.run(['rpm', '-qa', '--qf', '%{NAME} %{VERSION}\n'], stdout=subprocess.PIPE, text=True)
        return resultado.stdout.splitlines()
    except Exception as e:
        print(f"Error al ejecutar rpm -qa: {e}")
        return []

def obtener_paquetes_windows():
    try:
        resultado = subprocess.run([
            'powershell', '-Command',
            "Get-WmiObject Win32_Product | Select-Object Name, Version"
        ], stdout=subprocess.PIPE, text=True)
        return resultado.stdout.splitlines()
    except Exception as e:
        print(f"Error en PowerShell: {e}")
        return []

def filtrar_software(lineas, origen="dpkg"):
    software_relevante = []
    for linea in lineas:
        partes = linea.split()
        if origen == "windows":
            if len(partes) >= 2:
                nombre = " ".join(partes[:-1])
                version = partes[-1]
            else:
                continue
        elif origen == "dpkg":
            # Asegurar que es una línea válida de paquete
            if len(partes) >= 3 and partes[0] == "ii":
                nombre = partes[1]
                version = partes[2]
            else:
                continue
        else:
            if len(partes) >= 2:
                nombre = partes[0]
                version = partes[1]
            else:
                continue

        if any(keyword in nombre.lower() for keyword in KEYWORDS):
            software_relevante.append({"name": nombre, "version": version})
    return software_relevante


def guardar_json(lista, ruta):
    try:
        with open(ruta, "w") as f:
            json.dump(lista, f, indent=2)
        print(f"Software detectado guardado en {ruta}")
    except Exception as e:
        print(f"Error al guardar JSON: {e}")

def main():
    if len(sys.argv) < 2:
        print("Debes proporcionar el nombre base de salida.")
        sys.exit(1)
    nombre_base = sys.argv[1]
    sistema = detectar_sistema()

    if sistema == "debian":
        lineas = obtener_paquetes_dpkg()
        software = filtrar_software(lineas, origen="dpkg")
    elif sistema == "redhat":
        lineas = obtener_paquetes_rpm()
        software = filtrar_software(lineas, origen="rpm")
    elif sistema == "windows":
        lineas = obtener_paquetes_windows()
        software = filtrar_software(lineas, origen="windows")
    else:
        print("Sistema no soportado.")
        sys.exit(1)

    ruta_json = f"softwares/softwareTotal_{nombre_base}.json"
    print(f"[INFO] Total software detectado tras filtro: {len(software)}")
    if len(software) == 0:
        print("[DEBUG] Ejemplo de líneas recibidas:")
        for l in lineas[:10]:
            print(l)

    guardar_json(software, ruta_json)

    # Usar limpiarSW.py solo en sistemas Linux
    if sistema in ["debian", "redhat"]:
        subprocess.run(["python3", "src/limpiarSW.py", nombre_base])

if __name__ == "__main__":
    main()