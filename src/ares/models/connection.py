import random
from dataclasses import dataclass, field


class IdentificationCommands:
    def __init__(self):
        self._choices = ["hostnamectl", "sw_vers", "ver"]

    def get_choice(self):
        return random.choice(self._choices)

    def remove_choice(self, choice: str):
        self._choices.remove(choice)


@dataclass
class ExtractCommands:
    MAC: str = (
        "system_profiler SPApplicationsDataType | grep  'Version:' -B 2"
    )


@dataclass
class Server:
    hostname: str
    port: int
    username: str
    password: str


@dataclass
class Application:
    name: str
    version: str
    operating_system: str
    cve: list = field(default_factory=list)
