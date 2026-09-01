# state.py

from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    so: str = "Unknown"
    os_method: str = "Unknown"
    ports: list = field(default_factory=list)
    compromised: bool = False
    access: object = None
    exploited: bool = False


@dataclass
class CredentialCandidate:
    username: str | None = None
    secret: str | None = None
    nt_hash: str | None = None
    source: str = ""
    location: str = ""
    evidence: str = ""


class State:
    def __init__(self):
        self.hosts = {}
        self.credentials = []
        self.flag = None
        self.flag_path = None

    def register(self, host):
        if host.ip not in self.hosts:
            self.hosts[host.ip] = host

    def mark_compromised(self, ip, access=None):
        if ip not in self.hosts:
            self.hosts[ip] = Host(ip=ip)

        self.hosts[ip].compromised = True

        if access is not None:
            self.hosts[ip].access = access

    def next_pending(self):
        for h in self.hosts.values():
            if h.compromised and not h.exploited:
                return h

        return None