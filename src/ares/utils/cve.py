import os
import subprocess
import time
from typing import Dict

from ares.models.connection import Application

class SearchSploitContext:
    def __init__(self, know_apps: Dict[str, Application]):
        self._known_apps: Dict[str, Application]= know_apps

    def retrieve_cve(self):
        for app_name, app in self._known_apps.items():
            app: Application = app
            print(f"Searching public exploits for app '{app_name}'")
            process = subprocess.run(f"searchsploit -c '{app_name}'", shell=True, encoding="utf-8", capture_output=True)

            if not process.__getattribute__("stdout"):
                print("No match")
                print()
                continue

            response = process.stdout

            if app.version in response:
                print(f"Possible match {response}")
            time.sleep(1)
            print()