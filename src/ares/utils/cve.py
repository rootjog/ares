import os
import time
from typing import Dict, List, Union
from urllib.parse import quote_plus

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
                response = self.request_opencve(
                    app_name=app_name,
                    page=page,
                    original_version=app.version,
                    subversion=1,
                )

                if response.get("next", None) is not None:
                    _next: List = response["next"].split("?")[1].split("&")
                    for query_param in _next:
                        if "page" not in query_param:
                            continue
                        page = query_param.split("=")[1]

                if len(response.get("results", [])) == 0:
                    print("Couldn't find exploits for the given application.")
                    break

                app.cve.extend(
                    list(map(lambda cve: CVE(**cve), response["results"]))
                )

                if int(page) == 5:
                    break

                if int(page) == int(last_visited_page):
                    break
                time.sleep(1)

    def request_opencve(
        self,
        app_name: str,
        page: int,
        original_version: str,
        subversion: int,
        last_response: Union[Dict | None] = None,
    ):
        if subversion >= len(original_version) + 1:
            return last_response
        version = original_version[0:subversion]
        print(
            "GET "
            f"{self._base_url}?search="
            f"{quote_plus(app_name)}+{version}&page={page}"
        )
        response = requests.get(
            f"{self._base_url}?search="
            f"{quote_plus(app_name)}+{version}&page={page}",
            headers=self.headers,
            auth=(
                os.environ["OPENCVE_AUTH"].split(":")[0],
                os.environ["OPENCVE_AUTH"].split(":")[1],
            ),
        )
        response = response.json()
        if last_response is None:
            last_response = response

        if len(response.get("results", [])) > 0:
            # Version must match exactly.
            return self.request_opencve(
                app_name=app_name,
                page=page,
                original_version=original_version,
                subversion=subversion + 1,
                last_response=response,
            )

        return last_response
