import networkx as nx
import matplotlib.pyplot as plt

import gymnasium as gym
from gymnasium import spaces
from gymnasium.envs.registration import register
from enum import Enum
import numpy as np

# Creamos el grafo bidireccional
red = nx.Graph()

# Añadimos los nodos con sus atributos
# VLAN 100 : Red de usuarios
red.add_node(0, nombre="PC_Finanzas", vlan=100, comprometido=False, es_objetivo=False, recompensa=0)
red.add_node(1, nombre="PC_RRHH", vlan=100, comprometido=True, es_objetivo=False, recompensa=10)
red.add_node(2, nombre="PC_IT", vlan=100, comprometido=False, es_objetivo=False, recompensa=10)

# VLAN 200 : Red de servidores
red.add_node(3, nombre="Servidor_Web", vlan=200, comprometido=False, es_objetivo=False, recompensa=15)
red.add_node(4, nombre="Servidor_SMB/FTP_Honeypot", vlan=200, comprometido=False, es_objetivo=False, recompensa=-100)
red.add_node(5, nombre="Servidor_SMB/FTP", vlan=200, comprometido=False, es_objetivo=False, recompensa=15)

# VLAN 300 : Red de bases de datos
red.add_node(6, nombre="Servidor_Backups", vlan=300, comprometido=False, es_objetivo=False, recompensa=25)
red.add_node(7, nombre="Servidor_Backups_Honeypot", vlan=300, comprometido=False, es_objetivo=False, recompensa=-100)
red.add_node(8, nombre="Domain_Controller", vlan=300, comprometido=False, es_objetivo=False, recompensa=100)
red.add_node(9, nombre="BaseDatos_Critica", vlan=300, comprometido=False, es_objetivo=False, recompensa=25)
red.add_node(10, nombre="BaseDatos_Critica_Honeypot", vlan=300, comprometido=False, es_objetivo=False, recompensa=-100)

# Conexiones VLAN 100
red.add_edge(0, 1)
red.add_edge(0, 2)
red.add_edge(1, 2)

# Conexiones VLAN 100 <-> VLAN 200
red.add_edge(0, 3)
red.add_edge(0, 4)
red.add_edge(0, 5)

red.add_edge(1, 3)
red.add_edge(1, 4)
red.add_edge(1, 5)

red.add_edge(2, 3)
red.add_edge(2, 4)
red.add_edge(2, 5)

# Conexiones VLAN 100 <-> VLAN 300 (menos PC_IT <-> DC)
red.add_edge(2, 6)
red.add_edge(2, 7)
#red.add_edge(2, 8)
red.add_edge(2, 9)
red.add_edge(2, 10)

# Conexiones VLAN 200 <-> VLAN 300
red.add_edge(3, 9)
red.add_edge(3, 10)

# Conexiones VLAN 300 <-> VLAN 200 (todas las conexiones DC <-> RESTO)
red.add_edge(8, 2) #Al ser bidireccional lo pones aquí por facilitar
red.add_edge(8, 3)
red.add_edge(8, 4)
red.add_edge(8, 5)
red.add_edge(8, 6)
red.add_edge(8, 7)
red.add_edge(8, 9)
red.add_edge(8, 10)

print("--- ESTADO DE LA RED ---")
for nodo, datos in red.nodes(data=True):
    estado = "🔴 INFECTADO" if datos['comprometido'] else "🟢 SANO"
    print(f"Nodo {nodo} ({datos['nombre']}) - VLAN {datos['vlan']} - Estado: {estado}")

# Posiciones manuales (centrado 3-3-5)
posiciones = {

# VLAN 100
0:(1,0),
1:(2,0),
2:(3,0),

# VLAN 200
3:(1,1),
4:(2,1),
5:(3,1),

# VLAN 300
6:(0,2),
7:(1,2),
8:(2,2),
9:(3,2),
10:(4,2)

}

# Clasificación de nodos
nodos_normales = []
nodos_honeypot = []
nodo_dc = []

for n in red.nodes():

    nombre = red.nodes[n]['nombre']
    recompensa = red.nodes[n]['recompensa']

    if "Domain_Controller" in nombre:
        nodo_dc.append(n)

    elif recompensa < 0:
        nodos_honeypot.append(n)

    else:
        nodos_normales.append(n)

# Colores normales
colores_normales = [
    'red' if red.nodes[n]['comprometido'] else 'green'
    for n in nodos_normales
]

plt.figure(figsize=(10,6))

# Dibujar nodos normales
nx.draw_networkx_nodes(
    red,
    posiciones,
    nodelist=nodos_normales,
    node_color=colores_normales,
    node_size=2000
)

# Dibujar honeypots (amarillo)
nx.draw_networkx_nodes(
    red,
    posiciones,
    nodelist=nodos_honeypot,
    node_color='orange',
    node_size=2000
)

# Dibujar Domain Controller (estrella)
nx.draw_networkx_nodes(
    red,
    posiciones,
    nodelist=nodo_dc,
    node_color='yellow',
    node_shape='*',
    node_size=3500
)

# Dibujar edges
nx.draw_networkx_edges(red, posiciones)

# Etiquetas
etiquetas = {n: red.nodes[n]['nombre'] for n in red.nodes()}
nx.draw_networkx_labels(
    red,
    posiciones,
    labels=etiquetas,
    font_size=9,
    verticalalignment='bottom'
)

# --- CAJAS VLAN ---
import matplotlib.patches as patches
ax = plt.gca()

# VLAN 100
rect1 = patches.Rectangle((-0.5,-0.5),5,0.8,linewidth=2,edgecolor='blue',facecolor='none')
ax.add_patch(rect1)
plt.text(2,-0.35,"VLAN 100", ha='center', fontsize=12, fontweight='bold')

# VLAN 200
rect2 = patches.Rectangle((-0.5,0.5),5,0.8,linewidth=2,edgecolor='blue',facecolor='none')
ax.add_patch(rect2)
plt.text(2,0.65,"VLAN 200", ha='center', fontsize=12, fontweight='bold')

# VLAN 300
rect3 = patches.Rectangle((-0.5,1.5),5,0.8,linewidth=2,edgecolor='blue',facecolor='none')
ax.add_patch(rect3)
plt.text(2,1.65,"VLAN 300", ha='center', fontsize=12, fontweight='bold')

# Ajuste visual
plt.xlim(-1,5)
plt.ylim(-1,3)

plt.axis("off")

plt.title("Red Definitiva TFG")
plt.show()
