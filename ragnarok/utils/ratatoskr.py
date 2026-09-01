# utils/ratatoskr.py

BANNER = r"""
    ████   ███  █████  ███  █████  ███   ████ █   █ ████    
    █░░░█ █ ░░█  ░█░░░█ ░░█  ░█░░░█ ░░█ █ ░░░░█░ █ ░█░░░█   
    ████░░█████░  █░░░█████░  █░░░█░ ░█░ ███░░███ ░ ████░░  
    █░░█░ █░░░█░░ █░░ █░░░█░░ █░░ █░░ █░░ ░░█ █░░█ ░█░░█░ ░ 
    █░░░█░█░░░█░░ █░░ █░░░█░░ █░░  ███ ░████░░█░░░█ █░░░█░  
     ░░  ░ ░░  ░░  ░░  ░░  ░░  ░░   ░░░ ░░░░░ ░░░  ░ ░░  ░  
      ░   ░ ░   ░   ░   ░   ░   ░    ░░░  ░░░░  ░   ░ ░   ░  
    
          ⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡴⠒⡚⠿⡏⢹⣙⢓⡲⠦⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⢀⡴⡺⢥⠘⠋⠲⢇⢤⡟⢻⢄⣼⠑⣀⠢⣊⢓⢦⡀⠀⠀⠀⠀⠀
          ⠀⠀⠀⢀⣔⢁⠀⣠⣭⠷⣘⠋⠘⡎⢸⣸⢊⣧⠞⢓⣠⣧⠼⣛⠽⢦⡀⠀⠀⠀
          ⠀⠀⣠⢏⣹⠓⡟⢲⡤⠴⠾⣦⣸⣇⣸⠋⢈⡇⡴⢁⣆⢸⣱⣸⠤⠤⠿⣄⠀⠀
          ⠀⣰⣃⢽⢨⠋⠃⢿⡤⢤⣾⠹⠙⢿⡁⠀⢠⠇⣧⡼⠾⡞⠭⠷⠣⣌⠉⠙⡆⠀
          ⢠⣧⠛⠒⡟⠊⢠⠟⠀⣫⡂⠱⡦⠈⣿⢀⣾⠿⠉⢧⡀⢀⡧⠼⣕⠺⡛⠶⢾⡀
          ⡼⠘⠙⢒⡧⣶⢻⣦⠄⣼⡁⠀⠁⢀⣿⣿⠃⠀⠀⢀⠛⢛⣮⣽⣾⢗⣛⢗⣀⣇
          ⣧⢤⡿⢾⠘⡏⠈⠀⠉⠃⠁⠀⠀⢸⣿⢹⡀⠰⠒⠉⠧⠄⠈⠟⢆⠟⣎⣀⡀⢹
          ⣿⣦⠃⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠙⠼⠻⢽⣉⣿
          ⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡷⢻⣿⣿⣄⣀⣀⣀⡀⠀⠀⠀⠀⠀⠱⡏
          ⠘⣿⣦⣄⠀⠀⠀⠀⣀⣤⣀⣠⡴⣚⣵⣿⣿⣿⣿⣷⣖⠪⠿⣗⠦⠴⣾⣿⣿⠃
          ⠀⠹⣿⣿⣷⡶⠶⡾⠝⠂⣹⣿⣿⢿⣿⣿⣿⡇⢹⣿⠉⢳⣦⡘⣎⢻⣿⣿⠇⠀
          ⠀⠀⠹⣿⣿⣮⢸⢋⣡⢐⡿⢿⠉⢸⣿⢻⠙⣧⡸⡹⣍⠲⣷⣭⣸⣿⣿⠋⠀⠀
          ⠀⠀⠀⠈⠻⣿⣿⣿⣧⣾⣷⣿⠀⣏⡟⢸⢦⡏⢻⠀⣿⣤⣿⣿⣿⠟⠁⠀⠀⠀
⠀         ⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣦⣾⣧⣼⣬⣧⣼⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⢿⣿⣿⣿⣿⡿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀

    ---------------------------------------------------------
            Central Event Messenger & Logger Module
                Author: Bruno Paniagua García
    ---------------------------------------------------------
"""

import sys
import time
from contextlib import contextmanager

_COLORS = {
    "success": "\033[38;5;46m",    # verde intenso
    "info": "\033[38;5;39m",       # azul cian
    "warning": "\033[38;5;214m",   # naranja
    "error": "\033[38;5;196m",     # rojo intenso
    "debug":   "\033[95m",         # magenta
    "time": "\033[38;5;244m",      # gris neutro
}
_RESET = "\033[0m"
_USE_COLOR = sys.stdout.isatty()
_START = time.monotonic()


def _stamp():
    e = time.monotonic() - _START
    return f"{int(e // 60):02d}:{int(e % 60):02d}"


def _emit(kind, prefix, message, tag=None):
    ts = _stamp()
    if _USE_COLOR:
        tagpart = f"\033[1m{_COLORS[kind]}{tag}{_RESET} " if tag else ""
        print(f"{_COLORS['time']}[{ts}]{_RESET} {_COLORS[kind]}{prefix}{_RESET} {tagpart}{message}")
    else:
        tagpart = f"{tag} " if tag else ""
        print(f"[{ts}] {prefix} {tagpart}{message}")

def success(message, tag=None): _emit("success", "[✓]", message, tag)
def info(message, tag=None):    _emit("info", "[i]", message, tag)
def warning(message, tag=None): _emit("warning", "[!]", message, tag)
def error(message, tag=None):   _emit("error", "[✗]", message, tag)
def debug(message, tag=None):   _emit("debug", "[DEBUG]", message, tag)


@contextmanager
def timer(label, tag=None):
    t0 = time.monotonic()
    try:
        yield
    finally:
        _emit("time", "[TIME]", f"{label}: {time.monotonic() - t0:.1f}s", tag)