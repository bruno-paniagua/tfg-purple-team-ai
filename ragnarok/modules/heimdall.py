# modules/heimdall.py

BANNER = r"""
       █   █ █████ ███ █   █ ████   ███  █     █       
       █░  █░█░░░░░ █░░██ ██░█░░░█ █ ░░█ █░    █░      
       █████░████░░░█░░█░█ █░█░░░█░█████░█░░   █░░     
       █░░░█░█░░░░  █░░█░░░█░█░░ █░█░░░█░█░░   █░░     
       █░░░█░█████░███░█░░ █░████ ░█░░░█░█████ █████   
        ░░  ░░░░░░░ ░░░ ░░  ░░░░░░ ░░░  ░░░░░░░ ░░░░░  
         ░   ░ ░░░░░ ░░░ ░   ░ ░░░░  ░   ░ ░░░░░ ░░░░░ 
    
                    ..,,;;;;;;,,,,
              .,;'';;,..,;;;,,,,,.''';;,..
           ,,''                    '';;;;,;''
          ;'    ,;@@;'  ,@@;, @@, ';;;@@;,;';.
         ''  ,;@@@@@'   ;@@@@; ''    ;;@@@@@;;;;
           ;;@@@@@;    '''         .,,;;;@@@@@@@;;;
          ;;@@@@@@;           , ';;;@@@@@@@@;;;.
           '';@@@@@,.  ,   .   ',;;;@@@@@@;;;;;;
              .   '';;;;;;;;;,;;;;@@@@@;;' ,.:;'
                 ''..,,     ''''    '  .,;'
                     ''''''::''''''''

    ---------------------------------------------------------
            Reconnaissance and Enumeration Module
                Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

import subprocess
import re

from state import Host
from utils import ratatoskr as log


def run_command(command):

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )
    except subprocess.TimeoutExpired:
        log.debug(f"heimdall: timeout en {' '.join(command)}")
        return None


def _open_port(stdout, port):
    return any(
        line.startswith(port) and "open" in line
        for line in stdout.splitlines()
    )


def _extract_alive_ips(stdout):
    ips = []
    for line in stdout.splitlines():
        if line.startswith("Nmap scan report for"):
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m:
                ips.append(m.group(1))
    return ips


def scan_services_and_ports(ip):

    result = run_command([
        "nmap", "-sS", "-sV", "-T4",
        "-p", "88,135,139,389,445,3389,5985",
        "--host-timeout", "60s", "--max-retries", "2",
        ip
    ])
    if not (result and result.returncode == 0):
        return [], ""

    ports = []
    for line in result.stdout.splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            ports.append({"puerto": int(m.group(1)), "servicio": m.group(2)})

    return ports, result.stdout


def os_discovery(ip, scan_stdout=""):

    # ====== 1. Fingerprinting de Nmap (mas fiable)  [requiere root -> "sudo python odin.py"] ======
    result = run_command(["nmap", "-O", "--osscan-guess", ip])
    if result and result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith(("Running:", "OS details:", "Aggressive OS guesses:")):
                if "Windows" in line:
                    return {"os": "Windows", "method": "Nmap"}
                elif "Linux" in line:
                    return {"os": "Linux", "method": "Nmap"}

    # ====== 2. Deteccion por servicios (REUTILIZA el escaneo previo) ======
    if scan_stdout:
        windows_ports = ["445/tcp", "139/tcp", "3389/tcp", "5985/tcp", "5986/tcp"]
        linux_ports   = ["22/tcp", "111/tcp", "2049/tcp"]
        if any(_open_port(scan_stdout, p) for p in windows_ports):
            return {"os": "Windows", "method": "Services"}
        elif any(_open_port(scan_stdout, p) for p in linux_ports):
            return {"os": "Linux", "method": "Services"}

    # ====== 3. Deteccion mediante TTL  [funciona sin root] ======
    result = run_command(["ping", "-c", "1", "-W", "1", ip])
    if result and result.returncode == 0:
        match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return {"os": "Linux", "method": "TTL"}
            elif ttl <= 128:
                return {"os": "Windows", "method": "TTL"}

    return {"os": "Unknown", "method": "Unknown"}


def discovery(environment):
    hosts = []

    # Paso 1: barrido de descubrimiento sobre el ambito que nos pasa Odin.
    scanning = run_command([
        "nmap", "-sn", "-PS445,139,135,88,389",
        "-T4", "--max-retries", "1", "--min-rate", "1000",
        environment
    ])
    if not (scanning and scanning.returncode == 0):
        return hosts

    # Paso 2: caracterizar cada maquina viva.
    for ip in _extract_alive_ips(scanning.stdout):
        ports, scan_stdout = scan_services_and_ports(ip)
        info = os_discovery(ip, scan_stdout)
        hosts.append(Host(
            ip=ip,
            so=info["os"],
            os_method=info["method"],
            ports=ports,
        ))

    return hosts
