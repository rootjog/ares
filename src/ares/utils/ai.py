from typing import Dict

from duckduckgo_search import DDGS
from paramiko import SSHClient
from rich.console import Console

from ares.models.connection import Application

console = Console()


class AIContext:
    def __init__(self, known_apps: Dict[str, Application]):
        self._known_apps: Dict[str, Application] = known_apps
        self._browser_engine: str = "https://duckduckgo.com"

    def gather_info(self):
        for _, app in self._known_apps.items():
            app: Application = app
            if len(app.cve) == 0:
                continue
            cves_names_and_descriptions = ",".join(
                list(
                    map(
                        lambda cve: f"{cve.cve_id} ({(cve.description)})",
                        sorted(
                            app.cve,
                            key=lambda x: x.cve_id,
                            reverse=True,
                        ),
                    )
                )
            )
            message = (
                "You are the best doing vulnerability scanning "
                f"in a {app.operating_system.upper()} operating system, "
                "the application I'm currently trying to "
                "pentest with owner permission "
                f"is {app.name} version {app.version}. "
                "It appears that this version"
                "is vulnerable "
                "to the following CVE (I'm including "
                f"the description): `({cves_names_and_descriptions})`, "
                "could you please generate a list of "
                "commands to exploit this application? "
                "Please send one line commands not "
                "listed ones, "
                "Note that I'm going to "
                "execute this commands by automatizating it, "
                "so give me a cool format "
                "where your comments have # at line start."
            )
            console.print(
                f"{app.name} - {cves_names_and_descriptions}",
                overflow="ellipsis",
            )
            results = DDGS().chat(
                keywords=message,
                model="llama-3.3-70b",
            )
            console.rule("AI Response")
            console.print(results)

            results = results.split("\n")
            console.rule("Commands to execute")
            for line in results:
                if line.startswith("#") or line == "```" or line == "":
                    continue
                self.exploit(client=app.client, command=line)
            console.print()

    def exploit(self, client: SSHClient, command: str):
        _, stdout, stderr = client.exec_command(command=command)
        console.print(command)
        console.print(f"stdout: {self.parse_response(stdout)}")
        console.print(f"stderr: {self.parse_response(stderr)}")

    def parse_response(self, data: bytes) -> str:
        return data.read().decode(encoding="utf-8")
