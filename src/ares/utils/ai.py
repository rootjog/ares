from typing import Dict

from ares.models.connection import Application


class AIContext:
    def __init__(self, known_apps: Dict[str, Application]):
        self._known_apps: Dict[str, Application] = known_apps

    def gather_info(self): ...

    def exploit(self): ...
