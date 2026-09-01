# tests/test_skadi.py (mueve test_skadi.py a la raíz del proyecto para probar -> python3 test_skadi.py)

from modules import skadi

# Loot simulado de PC_RRHH con rutas estilo Windows (backslash), tal y como devolvería la víctima real
FAKE_FS = {
    r"C:\Users\hrmanager\Desktop\passwords.txt":
        "Base de datos interna\nusername = sql_svc\npassword = <REDACTED>\n",
    r"C:\Users\hrmanager\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt":
        "dir\nAdministrator:OldP@ss2023\ncls\n",
    r"C:\Users\hrmanager\Documents\IT_Support\remote_access.rdp":
        "full address:s:10.100.0.20\nusername:s:ithelp\nprompt for credentials:i:0\n",
    r"C:\Users\hrmanager\Documents\IT_Support\readme.txt":
        "Acceso remoto soporte IT\nusername: ithelp\npassword: <REDACTED>\n",
    r"C:\Users\hrmanager\AppData\Local\Google\Chrome\User Data\Default\Login Data":
        "SQLite format 3 - blob DPAPI, no parseable en claro\n",
}

class FakeAccess:
    def list_files(self, directory, recurse=True):
        return [p for p in FAKE_FS if p.lower().startswith(directory.lower())]
    def file_size(self, path):
        return len(FAKE_FS.get(path, "").encode("utf-8"))
    def read_file(self, path):
        return FAKE_FS.get(path, "").encode("utf-8")

result = skadi.credential_hunt(FakeAccess())
print("status :", result["status"])
print("sources:", result["sources"])
for c in result["candidates"]:
    print(f"  {c.username or '(sin usuario)'} : {c.password}  [{c.source}]  {c.location}")