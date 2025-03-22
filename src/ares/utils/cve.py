import os
import time
from typing import Dict, List

import requests

from ares.models.connection import Application
from ares.models.cve import CVE


class OpenCVEContext:
    def __init__(self, know_apps: Dict[str, Application]):
        self._known_apps: Dict[str, Application] = know_apps
        self._base_url: str = "https://app.opencve.io/api/cve"
        self.headers = {
            "Accept": "application/json",
            "Host": "app.opencve.io",
        }

    def retrieve_cve(self):
        for app_name, app in self._known_apps.items():
            app: Application = app
            page = 1
            last_visited_page = 1
            while True:
                last_visited_page = page
                print(
                    "Storing public exploits for app "
                    f"'{app_name} (page: {page})'"
                )
                response = requests.get(
                    f"{self._base_url}?search={app_name}&page={page}",
                    headers=self.headers,
                    auth=(
                        os.environ["OPENCVE_AUTH"].split(":")[0],
                        os.environ["OPENCVE_AUTH"].split(":")[1],
                    ),
                )
                response = response.json()
                if "next" in response and response["next"] is not None:
                    _next: List = response["next"].split("?")[1].split("&")
                    for query_param in _next:
                        if "page" not in query_param:
                            continue
                        page = query_param.split("=")[1]

                app.cve.extend(
                    list(map(lambda cve: CVE(**cve), response["results"]))
                )

                if int(page) == 5:
                    break

                if int(page) == int(last_visited_page):
                    break
                time.sleep(1)
            break
