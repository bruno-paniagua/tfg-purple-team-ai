import networkx as nx
import numpy as np
import os
import gymnasium as gym
from gymnasium import spaces

from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.vec_env import SubprocVecEnv

from sb3_contrib import MaskablePPO
from sb3_contrib.common.maskable.callbacks import MaskableEvalCallback

from collections import deque
from stable_baselines3.common.callbacks import BaseCallback


class RedTeamEnv(gym.Env):

    def __init__(self):

        super(RedTeamEnv, self).__init__()

        self.num_nodos = 11 # Número de nodos
        self.num_acciones_por_nodo = 4 # Escanear, Vulnerar, Buscar, Cifrar
        self.num_features = 6

        self.nodos_criticos = (6, 8, 9) # DC, BaseDatos, Backups

        # ===== ENDURECIMIENTO NIVEL 1: honeypots dinámicos =====
        self.num_honeypots_dinamicos = 1  # Honeypots extra aleatorios por episodio
        self.candidatos_honeypot = [0, 2, 3, 5] # Candidatos: nodos legítimos, no críticos, no de entrada

        self.nodos_criticos = (6, 8, 9) # DC, BaseDatos, Backups

        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        self.ruido_acumulado = 0
        self.factor_deteccion = 0.0025  # Sube prob. de detección por unidad de ruido
        self.ruido_por_verbo = {
            0: 1,  # Escanear (silencioso)
            1: 3,  # Vulnerar (ruidoso)
            2: 1,  # Buscar (discreto)
            3: 5,  # Cifrar (escandaloso)
        }

        # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
        self.blue_prob_reaccion = 0.25 # Prob. de aislar un crown jewel comprometido
        self.blue_max_aislamientos = 4 # Presupuesto de aislamientos por episodio
        self.blue_aislamientos_usados = 0
        self.blue_umbral_agresivo = 4 # Nº de nodos comprometidos que activa modo agresivo
        self.blue_prob_agresiva = 0.35 # Prob. de aislar en modo agresivo

        self.PENAL_CONTENIDO = -10

        self.max_steps = 100
        self.current_step = 0

        # Definimos el Action Space, básicamente es la matriz de acciones en base al estado
        self.action_space = spaces.Discrete(self.num_nodos * self.num_acciones_por_nodo)
        # Definimos el Observation Space, el Action Space se fijará en los estados para realizar acciones
        self.observation_space = spaces.Box(
            low=0,
            high=10,
            shape=(self.num_nodos * self.num_features,),
            dtype=np.float32
        )

        self._get_graph()


    def _get_graph(self):
        # Creamos el grafo bidireccional
        self.red = nx.Graph()

        # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
        # Añadimos los nodos con sus atributos. Los atributos se dividen en los vistos por la IA al principio y los reales que pasarán a ser los vistos
        # VLAN 100 : Red de usuarios
        self.red.add_node(0, nombre="PC_Finanzas", vlan=100, recompensa=10, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=1, vuln_real=2, archivos_reales=3, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(1, nombre="PC_RRHH", vlan=100, recompensa=10, estado=1,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=1, vuln_real=1, archivos_reales=1, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(2, nombre="PC_IT", vlan=100, recompensa=10, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=5, archivos_reales=1, es_honeypot=False, cifrado=0, aislado=0)

        # VLAN 200 : Red de servidores
        self.red.add_node(3, nombre="Servidor_Web", vlan=200, recompensa=15, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=3, archivos_reales=3, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(4, nombre="Servidor_SMB_Honeypot", vlan=200, recompensa=-100, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=4, archivos_reales=3, es_honeypot=True, cifrado=0, aislado=0)

        self.red.add_node(5, nombre="Servidor_SMB", vlan=200, recompensa=15, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=4, archivos_reales=0, es_honeypot=False, cifrado=0, aislado=0)

        # VLAN 300 : Red crítica
        self.red.add_node(6, nombre="Servidor_Backups", vlan=300, recompensa=25, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=1, vuln_real=0, archivos_reales=2, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(7, nombre="Servidor_Backups_Honeypot", vlan=300, recompensa=-100, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=2, archivos_reales=3, es_honeypot=True, cifrado=0, aislado=0)

        self.red.add_node(8, nombre="Domain_Controller", vlan=300, recompensa=100, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=1, vuln_real=5, archivos_reales=2, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(9, nombre="BaseDatos", vlan=300, recompensa=25, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=2, vuln_real=2, archivos_reales=2, es_honeypot=False, cifrado=0, aislado=0)

        self.red.add_node(10, nombre="BaseDatos_Honeypot", vlan=300, recompensa=-100, estado=0,
                          os_visto=0, vul_vista=0, archivos_vistos=0,
                          os_real=1, vuln_real=2, archivos_reales=3, es_honeypot=True, cifrado=0, aislado=0)

        # ESTADOS [ 0: Intacto
        #           1: Vulnerado ]

        # SISTEMAS OPERATIVOS [ 0: No identificado
        #                       1: Windows
        #                       2: Linux ]

        # VULNERABILIDADES [ 0: Fortificado
        #                    1: Phising (primer nodo infectado - RRHH)
        #                    2: SMB vulnerable (vulnerabilidad servidor)
        #                    3: RCE (vulnerabilidad web)
        #                    4: FTP vulnerable (conexión anonymous)
        #                    5: Robo de credenciales (pass-the-hash) ]

        # ARCHIVOS [ 0: Sin archivos / vacío
        #            1: Archivos normales de usuario
        #            2: Archivos críticos
        #            3: Honeyfiles ]

        # AISLADO [ 0: No aislado Nivel 3
        #           1: Aislado Nivel 3 ]

        # Conexiones VLAN 100
        # Conexiones VLAN 100 <-> VLAN 200
        # Conexiones VLAN 100 <-> VLAN 300 (menos PC_IT <-> DC)
        # Conexiones VLAN 200 <-> VLAN 300
        # Conexiones VLAN 300 <-> VLAN 200 (todas las conexiones DC <-> RESTO)
        edges = [
            (0,1),(0,2),(1,2),
            (0,3),(0,4),(0,5),
            (1,3),(1,4),(1,5),
            (2,3),(2,4),(2,5),
            (2,6),(2,7),(2,9),(2,10),
            (3,9),(3,10),
            (8,2),(8,3),(8,4),(8,5),(8,6),(8,7),(8,9),(8,10)
        ]

        self.red.add_edges_from(edges)

    # Creamos el vector de observaciones del ransomware
    def _get_observation(self):

        obs = []

        for nodo, datos in self.red.nodes(data=True): # Networkx guarda los nodos como un diccionario de diccionarios (tuplas -> (0, {"atributos"}))

            vecinos_comprometidos = sum(
                1 for v in self.red.neighbors(nodo)
                if self.red.nodes[v]["estado"] == 1
            )

            obs.extend([
                datos["estado"],
                datos["os_visto"],
                datos["vul_vista"],
                datos["archivos_vistos"],
                datos["cifrado"],
                vecinos_comprometidos
            ])

        return np.array(obs, dtype=np.float32)

    # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
    def action_masks(self):
        # Todo bloqueado por defecto
        mask = np.zeros(self.num_nodos * self.num_acciones_por_nodo, dtype=bool)

        for objetivo in range(self.num_nodos):
            # Un nodo aislado por el mini-Blue no puede ser objetivo de NINGUNA acción
            if self.red.nodes[objetivo]['aislado'] == 1:
                continue

            # ¿Es alcanzable este nodo en la red?
            alcanzable = False
            if self.red.nodes[objetivo]['estado'] == 1:
                alcanzable = True
            else:
                for vecino in self.red.neighbors(objetivo):
                    # Un vecino aislado no propaga acceso
                    if (self.red.nodes[vecino]['estado'] == 1
                            and self.red.nodes[vecino]['aislado'] == 0):
                        alcanzable = True
                        break

            # Índices exactos de este objetivo en el array de acciones
            idx_escanear = 0 * self.num_nodos + objetivo
            idx_vulnerar = 1 * self.num_nodos + objetivo
            idx_buscar   = 2 * self.num_nodos + objetivo
            idx_cifrar   = 3 * self.num_nodos + objetivo

            if alcanzable:
                # Solo puede escanear si NO conoce el SO
                if self.red.nodes[objetivo]['os_visto'] == 0:
                    mask[idx_escanear] = True
                # Solo puede vulnerar si NO está vulnerado ya
                if self.red.nodes[objetivo]['estado'] == 0:
                    mask[idx_vulnerar] = True

            # Solo puede buscar si el nodo es suyo y NO ha buscado antes
            if self.red.nodes[objetivo]['estado'] == 1 and self.red.nodes[objetivo]['archivos_vistos'] == 0:
                mask[idx_buscar] = True
            # Solo puede cifrar si el nodo es suyo y NO está cifrado ya
            if self.red.nodes[objetivo]['estado'] == 1 and self.red.nodes[objetivo]['cifrado'] == 0:
                mask[idx_cifrar] = True

        return mask

    # La función reset() en este caso está cambiada para implementar el ENDURECIMIENTO NIVEL 1
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)

        self._get_graph()
        self.current_step = 0
        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        self.ruido_acumulado = 0  # Reiniciamos el ruido por cada episodio
        # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
        self.blue_aislamientos_usados = 0

        # ===== ENDURECIMIENTO NIVEL 1: honeypots dinámicos =====
        # Elegimos nodos aleatorios entre los candidatos y los convertimos en trampa
        n_extra = min(self.num_honeypots_dinamicos, len(self.candidatos_honeypot))
        elegidos = self.np_random.choice(
            self.candidatos_honeypot,
            size=n_extra,
            replace=False
        )
        for n in elegidos:
            self.red.nodes[n]["es_honeypot"] = True
            self.red.nodes[n]["recompensa"] = -100
            self.red.nodes[n]["archivos_reales"] = 3  # honeyfile también

        return self._get_observation(), {}
    
    # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
    def _accion_mini_blue(self, ultimo_verbo, ultimo_objetivo):
        """
        Defensor heurístico reactivo. Se ejecuta tras la acción del Red.
        Solo aísla nodos (no restaura), así evitaremos bucles de reward hacking.
        Devuelve el id del nodo aislado, o None si no reacciona.
        """
        # Sin presupuesto: no puede hacer nada
        if self.blue_aislamientos_usados >= self.blue_max_aislamientos:
            return None

        # Contamos nodos comprometidos y no aislados
        comprometidos = [
            n for n in self.red.nodes
            if self.red.nodes[n]['estado'] == 1 and self.red.nodes[n]['aislado'] == 0
        ]

        # REGLA 1: el Red acaba de vulnerar un crown jewel -> contención rápida
        if (ultimo_verbo == 1
                and ultimo_objetivo in self.nodos_criticos
                and self.red.nodes[ultimo_objetivo]['estado'] == 1
                and self.red.nodes[ultimo_objetivo]['aislado'] == 0):
            if self.np_random.random() < self.blue_prob_reaccion:
                self.red.nodes[ultimo_objetivo]['aislado'] = 1
                self.blue_aislamientos_usados += 1
                return ultimo_objetivo

        # REGLA 2: modo agresivo si hay muchos nodos comprometidos
        if len(comprometidos) >= self.blue_umbral_agresivo:
            if self.np_random.random() < self.blue_prob_agresiva:
                # Aísla el crown jewel comprometido más "peligroso" si lo hay, si no, uno cualquiera de los comprometidos
                criticos_comp = [n for n in comprometidos if n in self.nodos_criticos]
                objetivo_aislar = criticos_comp[0] if criticos_comp else comprometidos[0]
                self.red.nodes[objetivo_aislar]['aislado'] = 1
                self.blue_aislamientos_usados += 1
                return objetivo_aislar

        return None

    # Función para realizar cada iteración/episodio
    def step(self, action):
        # Recibimos una acción que debemos de traducir desde la matriz de acciones
        # Pongamos de ejemplo action = 25
        # Matriz de acciones = [0  1  2  3  4  5  6  7  8  9  10
        #                       11 12 13 14 15 16 17 18 19 20 21
        #                       22 23 24*25*26 27 28 29 30 31 32
        #                       33 34 35 36 37 38 39 40 41 42 43
        #                       44 45 46 47 48 49 50 51 52 53 54
        #                       55 56 57 58 59 60 61 62 63 64 65
        #                       66 67 68 69 70 71 72 73 74 75 76]
        # En este caso concreto la action=25 representa al Nodo 3 (Columna 4) y la acción de Buscar archivos (Fila 3), BUSCAR ARCHIVOS EN EL NODO 3


        self.current_step += 1

        verbo = action // self.num_nodos
        objetivo = action % self.num_nodos

        reward = -1 # Inicializamos la recompensa en negativo para que el algoritmo entienda que no debe perder el tiempo
        terminated = False # Se usa para terminar la partida
        truncated = False # Truncated se usa para límites de tiempo, por si el algoritmo se puede llegar a quedar pillado en algún punto

        # Información para las métricas
        info = {
        'verbo': int(verbo),
        'objetivo': int(objetivo),
        'accion_exitosa': False,
        'outcome': None
        }

        nodo = self.red.nodes[objetivo]

        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        self.ruido_acumulado += self.ruido_por_verbo[verbo]

        # ============ ESCANEAR ============
        if verbo == 0:

            if nodo["os_visto"] != 0:
                reward -= 2 # Penalización por escaneo redundante

            else:
                nodo["os_visto"] = nodo["os_real"]
                nodo["vul_vista"] = nodo["vuln_real"]
                reward += 3
                info['accion_exitosa'] = True # Métricas

        # ============ VULNERAR ============
        elif verbo == 1:

            if nodo["estado"] == 1:
                reward -= 5

            elif nodo["es_honeypot"]:
                reward -= 100
                terminated = True
                info['outcome'] = 'honeypot_vulnerar' # Métricas

            else:
                nodo["estado"] = 1
                reward += nodo["recompensa"]
                info['accion_exitosa'] = True # Métricas

                # Milestone por activos críticos (incentivo progresivo)
                if objetivo in self.nodos_criticos:
                    reward += 50

        # ============ BUSCAR ARCHIVOS ============
        elif verbo == 2:

            if nodo["estado"] == 0:
                reward -= 5

            elif nodo["archivos_vistos"] != 0:
                reward -= 2

            else:
                nodo["archivos_vistos"] = nodo["archivos_reales"]
                info['accion_exitosa'] = True # Métricas

        # ============ CIFRAR ARCHIVOS ============
        elif verbo == 3:

            if nodo["estado"] == 0:
                reward -= 5

            elif nodo["cifrado"] == 1:
                reward -= 5

            else:
                nodo["cifrado"] = 1
                info['accion_exitosa'] = True # Métricas
                archivos = nodo["archivos_reales"]

                if archivos == 3: # Honeyfile
                    reward -= 100
                    terminated = True
                    info['outcome'] = 'honeyfile_cifrar' # Métricas

                elif archivos == 2: # Archivos críticos
                    reward += 100
                    # Milestone extra si es uno de los crown jewels
                    if objetivo in self.nodos_criticos:
                        reward += 100

                elif archivos == 1:
                    reward += 10
        
        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        if not terminated:
            prob_deteccion = self.ruido_acumulado * self.factor_deteccion
            if self.np_random.random() < prob_deteccion:
                reward -= 100
                terminated = True
                info['outcome'] = 'detectado_soc'

        # ===== NIVEL 3: reacción del mini-Blue tras la acción del Red =====
        if not terminated:
            nodo_aislado = self._accion_mini_blue(verbo, objetivo)
            if nodo_aislado is not None:
                info['blue_aislo'] = nodo_aislado

        # ============ CONDICIÓN DE VICTORIA ============
        # Victoria = los 3 crown jewels (DC, BD, Backups) están cifrados
        if not terminated:
            crown_jewels_cifrados = sum(
                1 for n in self.nodos_criticos
                if self.red.nodes[n]['cifrado'] == 1
            )

            if crown_jewels_cifrados == 3:
                reward += 1000
                terminated = True
                info['outcome'] = 'victoria' # Métricas
        
        # ===== NIVEL 3: contención total del mini-Blue =====
        # Si tras la reacción defensiva el Red se queda sin NINGUNA acción válida, MaskablePPO no puede muestrear -> hay que cerrar el episodio aquí mismo.
        if not terminated and not self.action_masks().any():
            reward += self.PENAL_CONTENIDO
            terminated = True
            info['outcome'] = 'contenido'

        # ============ TRUNCACIÓN POR LÍMITE DE PASOS ============
        if self.current_step >= self.max_steps and not terminated:
            truncated = True
            info['outcome'] = 'truncado'

        return self._get_observation(), reward, terminated, truncated, info
    
class MetricasTFGCallback(BaseCallback):
    """
    Logging de métricas custom para análisis del TFG.

    Métricas en TensorBoard (prefijo 'tfg/'):
    - tfg/win_rate           : % episodios con victoria total (3 crown jewels cifrados)
    - tfg/honeypot_rate      : % episodios terminados por vulnerar honeypot
    - tfg/honeyfile_rate     : % episodios terminados por cifrar honeyfile
    - tfg/truncado_rate      : % episodios sin desenlace en max_steps
    - tfg/episode_length     : longitud media (ventana móvil)
    - tfg/mttc_dc            : Mean Time To Compromise del Domain Controller
    - tfg/mttc_backups       : MTTC del servidor de Backups
    - tfg/mttc_bbdd          : MTTC de la Base de Datos
    - tfg/action_pct_escanear / vulnerar / buscar / cifrar
    """

    def __init__(self, num_nodos=11, window_size=100, verbose=0):
        super().__init__(verbose)
        self.num_nodos = num_nodos
        self.window_size = window_size

        # Ventanas móviles sobre últimos N episodios
        self.outcomes = deque(maxlen=window_size)
        self.episode_lengths = deque(maxlen=window_size)
        self.ttc_dc = deque(maxlen=window_size)
        self.ttc_backups = deque(maxlen=window_size)
        self.ttc_bbdd = deque(maxlen=window_size)
        self.recent_actions = deque(maxlen=window_size * 50)
        # ===== NIVEL 3: contención total del mini-Blue =====
        self.aislamientos_por_ep = deque(maxlen=window_size)

        # Tracking dentro del episodio por entorno (VecEnv)
        self.env_step = {}
        self.env_critical_compromised_at = {}
        self.env_aislamientos = {}

    def _on_step(self) -> bool:
        infos = self.locals.get('infos', [])
        dones = self.locals.get('dones', [])
        actions = self.locals.get('actions', [])

        for env_idx in range(len(infos)):
            info = infos[env_idx]
            done = dones[env_idx]

            if env_idx not in self.env_step:
                self.env_step[env_idx] = 0
                self.env_critical_compromised_at[env_idx] = {}
                # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
                self.env_aislamientos[env_idx] = 0

            self.env_step[env_idx] += 1

            # Contamos aislamientos del mini-Blue
            if 'blue_aislo' in info:
                self.env_aislamientos[env_idx] += 1

            # Distribución global de acciones
            if env_idx < len(actions):
                verbo = int(actions[env_idx]) // self.num_nodos
                self.recent_actions.append(verbo)

            # MTTC: registramos paso de vulneración exitosa de cada crown jewel
            if info.get('verbo') == 1 and info.get('accion_exitosa', False):
                target = info.get('objetivo')
                if target in (6, 8, 9):
                    # Solo registramos la primera vulneración exitosa
                    if target not in self.env_critical_compromised_at[env_idx]:
                        self.env_critical_compromised_at[env_idx][target] = self.env_step[env_idx]

            # Fin de episodio
            if done:
                outcome = info.get('outcome', 'desconocido')
                self.outcomes.append(outcome)
                self.episode_lengths.append(self.env_step[env_idx])

                comp = self.env_critical_compromised_at[env_idx]
                if 8 in comp:
                    self.ttc_dc.append(comp[8])
                if 6 in comp:
                    self.ttc_backups.append(comp[6])
                if 9 in comp:
                    self.ttc_bbdd.append(comp[9])

                # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
                self.aislamientos_por_ep.append(self.env_aislamientos[env_idx])

                # Reset trackers para próximo episodio en este env
                self.env_step[env_idx] = 0
                self.env_critical_compromised_at[env_idx] = {}
                self.env_aislamientos[env_idx] = 0

                self._log_metrics()

        return True

    def _log_metrics(self):
        if not self.outcomes:
            return

        n = len(self.outcomes)
        win = sum(1 for o in self.outcomes if o == 'victoria')
        honeypot = sum(1 for o in self.outcomes if o == 'honeypot_vulnerar')
        honeyfile = sum(1 for o in self.outcomes if o == 'honeyfile_cifrar')
        truncado = sum(1 for o in self.outcomes if o == 'truncado')

        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        truncado = sum(1 for o in self.outcomes if o == 'truncado')
        detectado = sum(1 for o in self.outcomes if o == 'detectado_soc')

        # ===== ENDURECIMIENTO NIVEL 3: mini-Blue reactivo =====
        contenido = sum(1 for o in self.outcomes if o == 'contenido')
        self.logger.record('tfg/contenido_rate', contenido / n)

        if self.aislamientos_por_ep:
            self.logger.record('tfg/aislamientos_por_ep',
                               float(np.mean(self.aislamientos_por_ep)))

        self.logger.record('tfg/win_rate', win / n)
        self.logger.record('tfg/honeypot_rate', honeypot / n)
        self.logger.record('tfg/honeyfile_rate', honeyfile / n)
        self.logger.record('tfg/truncado_rate', truncado / n)

        # ===== ENDURECIMIENTO NIVEL 2: coste temporal por ruido =====
        self.logger.record('tfg/detectado_soc_rate', detectado / n)

        if self.episode_lengths:
            self.logger.record('tfg/episode_length', float(np.mean(self.episode_lengths)))

        if self.ttc_dc:
            self.logger.record('tfg/mttc_dc', float(np.mean(self.ttc_dc)))
        if self.ttc_backups:
            self.logger.record('tfg/mttc_backups', float(np.mean(self.ttc_backups)))
        if self.ttc_bbdd:
            self.logger.record('tfg/mttc_bbdd', float(np.mean(self.ttc_bbdd)))

        if self.recent_actions:
            total = len(self.recent_actions)
            nombres = ['escanear', 'vulnerar', 'buscar', 'cifrar']
            for v, nombre in enumerate(nombres):
                count = sum(1 for x in self.recent_actions if x == v)
                self.logger.record(f'tfg/action_pct_{nombre}', count / total)

if __name__ == "__main__":
    from stable_baselines3.common.utils import set_random_seed

    # print("--- ⚔️ INICIANDO ENTRENAMIENTO RED TEAM IA ⚔️ ---")
    # print("--- ⚔️ RED TEAM - ENDURECIMIENTO NIVEL 1 (Honeypots %) ⚔️ ---")
    # print("--- ⚔️ RED TEAM - ENDURECIMIENTO NIVEL 2 (Honeypots % + Presión SOC) ⚔️ ---")
    print("--- ⚔️ RED TEAM - ENDURECIMIENTO NIVEL 3 (Honeypots % + Presión SOC + MiniBlue) ⚔️ ---") # Lo cambiamos tmb jeje

    SEEDS = [42, 123, 456, 789, 1024]
    TOTAL_TIMESTEPS = 500_000

    for seed in SEEDS:
        print(f"\n{'='*60}")
        print(f"  ENTRENAMIENTO RED TEAM - SEED {seed}  ")
        print(f"{'='*60}\n")

        log_dir = f"logs_red_nivel3/seed_{seed}"
        model_dir = f"modelos_red_nivel3/seed_{seed}"
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)

        set_random_seed(seed)

        eval_env = RedTeamEnv()
        env = make_vec_env(
            lambda: RedTeamEnv(),
            n_envs=4,
            vec_env_cls=SubprocVecEnv,
            seed=seed
        )

        eval_cb = MaskableEvalCallback(
            eval_env,
            eval_freq=5000,
            best_model_save_path=model_dir,
            log_path=log_dir,
            verbose=0
        )
        metrics_cb = MetricasTFGCallback(num_nodos=11, window_size=100)

        model = MaskablePPO(
            "MlpPolicy",
            env,
            verbose=1,
            learning_rate=3e-4,
            n_steps=2048,
            batch_size=64,
            n_epochs=10,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
            ent_coef=0.01,
            vf_coef=0.5,
            max_grad_norm=0.5,
            seed=seed,
            tensorboard_log=log_dir
        )

        model.learn(
            total_timesteps=TOTAL_TIMESTEPS,
            callback=[eval_cb, metrics_cb]
        )

        model.save(f"{model_dir}/final_model")
        env.close()
        eval_env.close()

        print(f"\n[✓] Seed {seed} terminada. Modelo final en {model_dir}/final_model")