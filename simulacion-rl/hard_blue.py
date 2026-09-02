import networkx as nx
import numpy as np
import gymnasium as gym
from gymnasium import spaces
import random
import os

from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.vec_env import SubprocVecEnv

from sb3_contrib import MaskablePPO
from sb3_contrib.common.maskable.callbacks import MaskableEvalCallback

from collections import deque
from stable_baselines3.common.callbacks import BaseCallback

class BlueTeamEnv(gym.Env):
    def __init__(self):
        super(BlueTeamEnv, self).__init__()

        self.num_nodos = 11
        self.num_acciones_por_nodo = 4 # Analizar, Aislar, Trampear y Restaurar
        
        # Lo que "ve" el Blue Team por cada nodo:
        # 1. ¿Es Honeypot?
        # 2. Nivel de alerta (0 a 3)
        # 3. Si está aislado actualmente (0 o 1)
        # 4. Si tiene un honeyfile desplegado por el Blue Team (0 o 1)
        # 5. Si ya ha sido analizado a fondo y sabemos su estado real (0 o 1)
        self.num_features = 5 

        self.max_steps = 50
        self.current_step = 0
        self.paso_red_team = 1 # Por dónde va el playbook del atacante

        # El Action Space es igual que el del Red Team (11 nodos * 4 acciones)
        self.action_space = spaces.Discrete(self.num_nodos * self.num_acciones_por_nodo)

        # El Observation Space
        self.observation_space = spaces.Box(
            low=0, high=5, 
            shape=(self.num_nodos * self.num_features,), 
            dtype=np.float32
        )

        # Cargamos varios Playbooks para que la IA no aprenda pasos repetitivos
        # BEST_MODEL - ruta aprendida por el Red Team óptimo
        self.playbook_redteam_bestmodel = [
            {"verbo": "vuln", "objetivo": 3},  # Vulnera S.Web
            {"verbo": "vuln", "objetivo": 9},  # Vulnera BaseDatos
            {"verbo": "lock", "objetivo": 9},  # Cifra BaseDatos
            {"verbo": "vuln", "objetivo": 2},  # Vulnera PC_IT
            {"verbo": "vuln", "objetivo": 6},  # Vulnera S.Backups
            {"verbo": "lock", "objetivo": 6},  # Cifra S.Backups
            {"verbo": "scan", "objetivo": 4},  # Escanea S.SMB_Honeypot
            {"verbo": "lock", "objetivo": 1},  # Cifra PC_RRHH
            {"verbo": "lock", "objetivo": 2},  # Cifra PC_IT
            {"verbo": "vuln", "objetivo": 8},  # Vulnera DC
            {"verbo": "lock", "objetivo": 8}   # Cifra DC (objetivo final)
        ]

        # RUTA AGRESIVA 1 - "Smash and Grab" inspirado en APTs modernos
        self.playbook_redteam_aggressive = [
            {"verbo": "vuln", "objetivo": 2},  # Pivote rápido a PC_IT
            {"verbo": "vuln", "objetivo": 9},  # Salto directo a BaseDatos
            {"verbo": "lock", "objetivo": 9},  # Cifra BD (1er crown jewel)
            {"verbo": "vuln", "objetivo": 6},  # Vulnera Backups
            {"verbo": "lock", "objetivo": 6},  # Cifra Backups (2º crown jewel)
            {"verbo": "vuln", "objetivo": 8},  # Vulnera DC
            {"verbo": "lock", "objetivo": 8}   # Cifra DC (3er crown jewel = derrota total)
        ]

        # RUTA AGRESIVA 2 - "Doble Extorsión Moderna"
        # Patrón de ransomware con búsqueda + cifrado en crown jewels
        self.playbook_redteam_extortion = [
            {"verbo": "vuln", "objetivo": 2},   # Pivote a PC_IT
            {"verbo": "vuln", "objetivo": 9},   # Vulnera BaseDatos
            {"verbo": "scan", "objetivo": 6},   # Reconocimiento Backups
            {"verbo": "vuln", "objetivo": 6},   # Vulnera Backups
            {"verbo": "lock", "objetivo": 9},   # Cifra BD
            {"verbo": "lock", "objetivo": 6},   # Cifra Backups
            {"verbo": "vuln", "objetivo": 8},   # Vulnera DC
            {"verbo": "lock", "objetivo": 8}    # Cifra DC = derrota total
        ]

        # RUTA RÁPIDA - ataque sigiloso buscando solo DC
        #self.playbook_redteam_fastmodel = [
         #  {"verbo": "vuln", "objetivo": 2},  # Vuln IT
         #  {"verbo": "vuln", "objetivo": 8},  # Vuln DC
        #   {"verbo": "lock", "objetivo": 8}   # Cifra DC
        #]

        # RUTA EXHAUSTIVA - ransomware ruidoso que cifra todo
        self.playbook_redteam_allmodel = [
            {"verbo": "lock", "objetivo": 1},  # Cifra PC_RRHH
            {"verbo": "vuln", "objetivo": 0},  # Vuln PC_Finanzas
            {"verbo": "lock", "objetivo": 0},  # Cifra PC_Finanzas
            {"verbo": "vuln", "objetivo": 3},  # Vulnera S.Web
            {"verbo": "lock", "objetivo": 3},  # Cifra S.Web
            {"verbo": "vuln", "objetivo": 9},  # Vuln BaseDatos
            {"verbo": "lock", "objetivo": 9},  # Cifra BaseDatos
            {"verbo": "scan", "objetivo": 10}, # Escanea BaseDatos_Honeypot
            {"verbo": "vuln", "objetivo": 2},  # Vulnera PC_IT
            {"verbo": "lock", "objetivo": 2},  # Cifra PC_IT
            {"verbo": "scan", "objetivo": 4},  # Escanea S.SMB_Honeypot
            {"verbo": "vuln", "objetivo": 5},  # Vulnera S.SMB
            {"verbo": "lock", "objetivo": 5},  # Cifra S.SMB
            {"verbo": "vuln", "objetivo": 6},  # Vulnera S.Backups
            {"verbo": "lock", "objetivo": 6},  # Cifra S.Backups
            {"verbo": "scan", "objetivo": 7},  # Escanea S.Backups_Honeypot
            {"verbo": "vuln", "objetivo": 8},  # Vulnera DC
            {"verbo": "lock", "objetivo": 8}   # Cifra DC
        ]

        self.playbooks_redteam = [
            self.playbook_redteam_bestmodel,
            #self.playbook_redteam_fastmodel,
            self.playbook_redteam_aggressive,
            self.playbook_redteam_extortion,
            self.playbook_redteam_allmodel
        ]

        # ===== ENDURECIMIENTO NIVEL 0: multi-acción Red Team =====
        self.red_acciones_por_turno = 5 # Breakout time (baseline conceptual = 1)
        self.red_prob_evasion_honeyfile = 0.35 # Prob. de que el Red EVADA el honeyfile. Sube -> trampas menos fiables.

        self._get_graph()

    def _get_graph(self):
        
        # Creamos el grafo bidireccional
        self.red = nx.Graph()

        # Añadimos los nodos con sus atributos. Los atributos se dividen en los vistos por la IA al principio y los reales que pasarán a ser los vistos
        # VLAN 100 : Red de usuarios
        self.red.add_node(0, nombre="PC_Finanzas", vlan=100, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(1, nombre="PC_RRHH", vlan=100, es_honeypot=False, estado=1, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(2, nombre="PC_IT", vlan=100, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        # VLAN 200 : Red de servidores
        self.red.add_node(3, nombre="Servidor_Web", vlan=200, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(4, nombre="Servidor_SMB_Honeypot", vlan=200, es_honeypot=True, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(5, nombre="Servidor_SMB", vlan=200, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        # VLAN 300 : Red crítica
        self.red.add_node(6, nombre="Servidor_Backups", vlan=300, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(7, nombre="Servidor_Backups_Honeypot", vlan=300, es_honeypot=True, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(8, nombre="Domain_Controller", vlan=300, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(9, nombre="BaseDatos", vlan=300, es_honeypot=False, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)

        self.red.add_node(10, nombre="BaseDatos_Honeypot", vlan=300, es_honeypot=True, estado=0, cifrado=0, nivel_alerta=0, aislado=0, honeyfile=0, analizado=0)
    
        # HONEYPOT [ FALSE: No es honeypot
        #            TRUE: Es honeypot]

        # ESTADOS [ 0: Sano
        #           1: Vulnerado]

        # CIFRADO [ 0: Archivos normales
        #           1: Archivos cifrados]

        # NIVEL ALERTA [ 0: Tranquilidad
        #                1: Falsa Alarma
        #                2: Alerta amarilla (leve)
        #                3: Alerta naranja (media)
        #                4: Alerta roja (grave)]

        # AISLADO [ 0: Conectado a la red
        #           1: Aislado de la red]

        # HONEYFILES [ 0: Sin trampas
        #              1: Trampa desplegada]

        # ANALIZADO [ 0: Blue Team "ciego"
        #             1: Blue Team ve la "realidad"]

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

    def _get_observation(self):
        obs = []
        for nodo, datos in self.red.nodes(data=True):
            obs.extend([
                datos["es_honeypot"],
                datos["nivel_alerta"],
                datos["aislado"],
                datos["honeyfile"],
                datos["analizado"]
            ])
        return np.array(obs, dtype=np.float32)
    
    def action_masks(self):
        # False = Acción bloqueada/prohibida. True = Acción permitida.
        mask = np.zeros(self.action_space.n, dtype=bool)

        for objetivo in range(self.num_nodos):
            nodo = self.red.nodes[objetivo]

            # Iteramos por las 4 acciones posibles de este nodo específico
            for verbo in range(self.num_acciones_por_nodo):
                
                # Esto es la operación inversa a lo que hacemos en el step()
                accion_idx = verbo * self.num_nodos + objetivo

                # VERBO 0: ANALIZAR
                if verbo == 0:
                    # Siempre permitimos a un analista SOC mirar los logs de un equipo.
                    mask[accion_idx] = True

                # VERBO 1: AISLAR
                elif verbo == 1:
                    if nodo['aislado'] == 0: # Es absurdo intentar aislar un PC que ya tiene el cable cortado
                        mask[accion_idx] = True

                # VERBO 2: TRAMPEAR (Poner Honeyfile)
                elif verbo == 2:
                    if nodo['honeyfile'] == 0: # No tiene sentido poner un cebo donde ya hay uno puesto
                        mask[accion_idx] = True

                # VERBO 3: RESTAURAR
                elif verbo == 3:
                    if nodo['nivel_alerta'] > 0 or nodo['aislado'] == 1 or nodo['analizado'] == 1:
                        mask[accion_idx] = True

        return mask
    
    # Reiniciamos el grafo después de cada episodio (ya sea por partida perdida o por ganada)
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)

        self._get_graph()
        self.current_step = 0
        self.paso_red_team = 0

        self.playbook_actual = random.choice(self.playbooks_redteam)

        # Falsos Positivos (excluimos al nodo 1 ya que es la entrada del ransomware)
        nodos_sanos = [n for n in range(11) if n != 1]
        nodos_ruidosos = random.sample(nodos_sanos, 2)
        
        for n in nodos_ruidosos:
            self.red.nodes[n]["nivel_alerta"] = 1 # Falsa alarma para despistar

        return self._get_observation(), {}
    
    # ===== ENDURECIMIENTO NIVEL 0: multi-acción Red Team =====
    def _avanzar_red_team(self):
        """
        Ejecuta UN paso del playbook del Red, o evalúa el desenlace si el
        playbook se ha agotado. Devuelve (reward_delta, terminado, outcome).
        outcome es None mientras el episodio siga vivo.
        """
        # ¿Playbook agotado? -> desenlace final del episodio
        if self.paso_red_team >= len(self.playbook_actual):
            crown_jewels = (6, 8, 9)
            cj_cifrados = sum(1 for n in crown_jewels if self.red.nodes[n]['cifrado'] == 1)
            if cj_cifrados == 0:
                return 300, True, 'victoria_blue'       # Victoria total del Blue
            elif cj_cifrados < 3:
                return 100, True, 'contencion_parcial'  # Contención parcial
            else:
                return -200, True, 'derrota_blue_cj'    # Red consumó el ataque

        # Si no, ejecutamos el paso actual del playbook
        reward_delta = 0
        terminado = False
        outcome = None

        verbo_red = self.playbook_actual[self.paso_red_team]["verbo"]
        objetivo_red = self.playbook_actual[self.paso_red_team]["objetivo"]
        nodo_red = self.red.nodes[objetivo_red]

        # VULNERAR
        if verbo_red == "vuln":
            if nodo_red['aislado'] == 1:
                reward_delta += 50  # Defensa funcionó
                nodo_red['nivel_alerta'] = 3
            else:
                nodo_red['estado'] = 1
                reward_delta -= 50
                nodo_red['nivel_alerta'] = 2
                if nodo_red['nombre'] == "Domain_Controller":
                    reward_delta -= 100

        # CIFRAR
        elif verbo_red == "lock":
            if nodo_red['honeyfile'] == 1 and random.random() >= self.red_prob_evasion_honeyfile:
                reward_delta += 150  # Red cae en el honeyfile
                nodo_red['nivel_alerta'] = 4
            elif nodo_red['honeyfile'] == 1:
                pass  # Red detecta el honeyfile y avanza sin efecto
            elif nodo_red['aislado'] == 1:
                reward_delta += 50
                nodo_red['nivel_alerta'] = 3
            elif nodo_red['cifrado'] == 0:
                nodo_red['cifrado'] = 1
                reward_delta -= 50
                nodo_red['nivel_alerta'] = 3
                crown_jewels = (6, 8, 9)
                cj_cifrados = sum(1 for n in crown_jewels if self.red.nodes[n]['cifrado'] == 1)
                if cj_cifrados == 3:
                    terminado = True
                    reward_delta -= 500
                    outcome = 'derrota_total'

        # ESCANEAR
        elif verbo_red == "scan":
            if nodo_red['es_honeypot']:
                nodo_red['nivel_alerta'] = 2
                reward_delta += 10

        self.paso_red_team += 1
        return reward_delta, terminado, outcome
    
    # Función para realizar cada iteración/episodio
    def step(self, action):
        # Recibimos una acción que debemos de traducir desde la matriz de acciones
        # Pongamos de ejemplo action = 33
        # Matriz de acciones = [0  1  2  3  4  5  6  7  8  9  10
        #                       11 12 13 14 15 16 17 18 19 20 21
        #                       22 23 24 25 26 27 28 29 30 31 32
        #                      *33*34 35 36 37 38 39 40 41 42 43]
        # En este caso concreto la action=33 representa al Nodo 0 (Columna 1) y la acción de Restaurar Nodo (Fila 4), RESTAURAR NODO 0

        self.current_step += 1

        verbo_blue = action // self.num_nodos
        objetivo_blue = action % self.num_nodos

        reward = -1
        terminated = False
        truncated = False

        info = {
            'verbo_blue': int(verbo_blue),
            'objetivo_blue': int(objetivo_blue),
            'accion_exitosa_blue': False,
            'outcome': None
        }

        nodo = self.red.nodes[objetivo_blue]

        # ============ FASE BLUE TEAM ============
        # ANALIZAR
        if verbo_blue == 0:
            nodo['analizado'] = 1
            if nodo['estado'] == 1 or nodo['cifrado'] == 1:
                reward += 20  # Descubrimiento real
                nodo['nivel_alerta'] = 3
                info['accion_exitosa_blue'] = True
            else:
                reward += 5  # Confirmar falsa alarma también vale
                nodo['nivel_alerta'] = 0
                info['accion_exitosa_blue'] = True

        # AISLAR
        elif verbo_blue == 1:
            if nodo['aislado'] == 0:
                nodo['aislado'] = 1
                if nodo['estado'] == 1:
                    reward += 30  # Aislar infectado, perfecto
                    info['accion_exitosa_blue'] = True
                else:
                    # Aislar nodo sano: penalización proporcional al "ciego que va"
                    if nodo['analizado'] == 1:
                        reward -= 10  # Aisló con conocimiento, error menor
                    else:
                        reward -= 30  # Aisló a ciegas, mal
            else:
                reward -= 10

        # TRAMPEAR (Honeyfiles)
        elif verbo_blue == 2:
            if nodo['honeyfile'] == 0:
                nodo['honeyfile'] = 1
                reward -= 5
                info['accion_exitosa_blue'] = True
            else:
                reward -= 10

        # RESTAURAR
        elif verbo_blue == 3:
            if nodo['estado'] == 1 or nodo['cifrado'] == 1 or nodo['aislado'] == 1:
                nodo['estado'] = 0
                nodo['cifrado'] = 0
                nodo['nivel_alerta'] = 0
                nodo['aislado'] = 0
                nodo['analizado'] = 0
                reward += 50
                info['accion_exitosa_blue'] = True
            else:
                reward -= 50

        # ============ FASE RED TEAM (multi-acción: NIVEL 0) ============
        # El ransomware automatiza varios pasos por cada acción del SOC.
        for _ in range(self.red_acciones_por_turno):
            if terminated:
                break
            reward_delta, terminado_red, outcome_red = self._avanzar_red_team()
            reward += reward_delta
            if outcome_red is not None:
                info['outcome'] = outcome_red
            if terminado_red:
                terminated = True
                break

        return self._get_observation(), reward, terminated, truncated, info


class MetricasBlueTFGCallback(BaseCallback):
    """
    Logging de métricas custom para el Blue Team.
    
    Métricas TensorBoard (prefijo 'tfg/'):
      - tfg/win_rate_blue          : % victorias totales (ningún crown jewel cifrado)
      - tfg/contencion_parcial     : % episodios con contención parcial
      - tfg/derrota_total_rate     : % episodios con 3 crown jewels cifrados
      - tfg/truncado_rate          : % episodios sin desenlace
      - tfg/episode_length         : longitud media
      - tfg/action_pct_analizar / aislar / trampear / restaurar
    """
    def __init__(self, num_nodos=11, window_size=100, verbose=0):
        super().__init__(verbose)
        self.num_nodos = num_nodos
        self.window_size = window_size

        self.outcomes = deque(maxlen=window_size)
        self.episode_lengths = deque(maxlen=window_size)
        self.recent_actions = deque(maxlen=window_size * 50)

        self.env_step = {}

    def _on_step(self) -> bool:
        infos = self.locals.get('infos', [])
        dones = self.locals.get('dones', [])
        actions = self.locals.get('actions', [])

        for env_idx in range(len(infos)):
            info = infos[env_idx]
            done = dones[env_idx]

            if env_idx not in self.env_step:
                self.env_step[env_idx] = 0

            self.env_step[env_idx] += 1

            if env_idx < len(actions):
                verbo = int(actions[env_idx]) // self.num_nodos
                self.recent_actions.append(verbo)

            if done:
                outcome = info.get('outcome', 'desconocido')
                self.outcomes.append(outcome)
                self.episode_lengths.append(self.env_step[env_idx])
                self.env_step[env_idx] = 0
                self._log_metrics()

        return True

    def _log_metrics(self):
        if not self.outcomes:
            return

        n = len(self.outcomes)
        win = sum(1 for o in self.outcomes if o == 'victoria_blue')
        parcial = sum(1 for o in self.outcomes if o == 'contencion_parcial')
        derrota_cj = sum(1 for o in self.outcomes if o == 'derrota_blue_cj')
        derrota_total = sum(1 for o in self.outcomes if o == 'derrota_total')
        truncado = sum(1 for o in self.outcomes if o == 'truncado')

        self.logger.record('tfg/win_rate_blue', win / n)
        self.logger.record('tfg/contencion_parcial', parcial / n)
        self.logger.record('tfg/derrota_blue_cj_rate', derrota_cj / n)
        self.logger.record('tfg/derrota_total_rate', derrota_total / n)
        self.logger.record('tfg/truncado_rate', truncado / n)

        if self.episode_lengths:
            self.logger.record('tfg/episode_length', float(np.mean(self.episode_lengths)))

        if self.recent_actions:
            total = len(self.recent_actions)
            nombres = ['analizar', 'aislar', 'trampear', 'restaurar']
            for v, nombre in enumerate(nombres):
                count = sum(1 for x in self.recent_actions if x == v)
                self.logger.record(f'tfg/action_pct_{nombre}', count / total)


if __name__ == "__main__":
    from stable_baselines3.common.utils import set_random_seed

    # print("--- 🛡️ INICIANDO ENTRENAMIENTO BLUE TEAM IA 🛡️ ---")
    print("--- 🛡️ BLUE TEAM - ENDURECIMIENTO NIVEL 0 (Multi-Acción Red Team x5) 🛡️ ---") # Lo cambiamos tmb jeje

    SEEDS = [42, 123, 456, 789, 1024]
    TOTAL_TIMESTEPS = 500_000

    for seed in SEEDS:
        print(f"\n{'='*60}")
        print(f"  ENTRENAMIENTO BLUE TEAM - SEED {seed}")
        print(f"{'='*60}\n")

        log_dir = f"logs_blue_nivel0/seed_{seed}"
        model_dir = f"modelos_blue_nivel0/seed_{seed}"
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)

        set_random_seed(seed)

        eval_env = BlueTeamEnv()
        env = make_vec_env(
            lambda: BlueTeamEnv(),
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
        metrics_cb = MetricasBlueTFGCallback(num_nodos=11, window_size=100)

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