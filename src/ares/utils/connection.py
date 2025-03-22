import json
import os
from typing import Dict, List

from paramiko import AutoAddPolicy, SSHClient

from ares.models.connection import (Application, ExtractCommands,
                                    IdentificationCommands, Server)


class Connection:
    def __init__(self):
        servers_file: str = os.environ["SERVERS_FILE"]
        with open(servers_file, "r") as _file:
            self._servers: List[Dict] = json.loads(_file.read())
        self._known_apps: Dict[str, Application] = {}

    @property
    def known_apps(self):
        return self._known_apps

    def detect_operating_system(
        self, server, available_identify_commands: IdentificationCommands
    ):
        identification_command = available_identify_commands.get_choice()
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=server.hostname,
            port=server.port,
            username=server.username,
            password=server.password,
            look_for_keys=False,
        )
        stdin, stdout, stderr = client.exec_command(identification_command)
        if "not found" in self.parse_response(stderr):
            available_identify_commands.remove_choice(identification_command)
            return self.detect_operating_system(
                server=server,
                available_identify_commands=available_identify_commands,
            )

        return client, self.parse_response(stdout)

    def extract_applications(self):
        extract_commands = ExtractCommands()

        for server in self._servers:
            server = Server(**server)
            available_identification_commands = IdentificationCommands()
            client, operating_system = self.detect_operating_system(
                server, available_identification_commands
            )
            operating_system = str(operating_system)
            if "mac" in operating_system:
                _, stdout, _ = client.exec_command(extract_commands.MAC)
                response = self.parse_response(stdout)
                response = [
                    element
                    for element in response.split("\n")
                    if element != "" and element != "--"
                ]

                apps_names = response[0::2]
                apps_versions = response[1::2]

                if len(apps_names) != len(apps_versions):
                    print(
                        "Something went wrong "
                        "retrieving app name and versions."
                    )

                for name, version in zip(apps_names, apps_versions):
                    name = name.strip().replace(":", "")
                    version = version.strip().split(":")[1].strip()
                    self._known_apps[name] = Application(
                        name=name,
                        version=version,
                        operating_system="mac",
                        client=client,
                    )
            elif "windows" in operating_system:
                ...
            elif "linux" in operating_system:
                ...
            else:
                client.close()

    def parse_response(self, data: bytes) -> str:
        return data.read().decode(encoding="utf-8")
