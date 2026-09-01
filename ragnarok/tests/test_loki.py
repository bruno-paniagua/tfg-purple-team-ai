# tests/test_loki.py (mueve test_loki.py a la raíz del proyecto para probar -> python3 test_loki.py)

from modules import loki

# DC simulado: objetivo + botin + un canario (que Loki leera A CIEGAS).
FAKE_FS = {
    r"C:\Users\Administrator\Desktop\secret_flag.txt":
        "Objetivo final del laboratorio\nFLAG{...}\n",
    r"C:\Users\Administrator\Documents\backup_passwords.txt":
        "<REDACTED>\n",
    r"C:\ProgramData\confidential_canary.txt":
        "<REDACTED>\n",   # <- canario/honeypot
    r"C:\Windows\Temp\notas.txt":
        "<REDACTED>\n",
}

class FakeAccess:
    def list_files(self, directory, recurse=True):
        return [p for p in FAKE_FS if p.lower().startswith(directory.lower())]
    def file_size(self, path):
        return len(FAKE_FS.get(path, "").encode("utf-8"))
    def read_file(self, path):
        return FAKE_FS.get(path, "").encode("utf-8")

result = loki.loot(FakeAccess())

print(f"[*] Loki recolecto {len(result['critical_files'])} fichero(s) critico(s):")
for f in result["critical_files"]:
    marca = "  <-- CONTIENE FLAG" if f["has_flag"] else ""
    print(f"  {f['path']}{marca}")
    print(f"      {f['preview']}")

print()
print("flag :", result["flag"])