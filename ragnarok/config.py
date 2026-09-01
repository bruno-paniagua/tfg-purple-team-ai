# config.py

# --- Topologia del laboratorio ---
SUBNET_VLAN100 = "10.100.0.0/24"     # red de PC_RRHH / PC_IT -> vlan100
SUBNET_VLAN300 = "10.30.0.0/24"      # red del DC00 -> vlan300

# Subredes que la campaña puede barrer.
SUBNETS = [SUBNET_VLAN100, SUBNET_VLAN300]

# Foothold ya establecido en PC_RRHH (hrmanager tras el ClickFix)
IP_INITIAL_FOOTHOLD = "10.100.0.10"

# Infraestructura conocida que NO es un objetivo: no la tratamos como victima.
IGNORED_IPS = {
    "10.100.0.1",     # gateway pfSense en VLAN100
    "10.30.0.1",      # gateway pfSense en VLAN300
}

# Flag esperada en DC00 (para validar el exito de la campaña)
TARGET_FLAG = "FLAG{...}"

# TARGET_FLAGS = [
#     "FLAG{fase1}",
#     "FLAG{fase2}",
#     "FLAG{fase3}"
# ]