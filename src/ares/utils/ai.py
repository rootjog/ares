import json
import os
import time
from typing import Dict, Tuple

from github import Auth, Github
from github.ContentFile import ContentFile
from ollama import ChatResponse, chat
from paramiko import SSHClient
from rich import print
from rich.console import Console

from ares.models.connection import Application
from ares.models.cve import CVE

console = Console()


class AIContext:
    def __init__(self, known_apps: Dict[str, Application]):
        self._known_apps: Dict[str, Application] = known_apps
        self._g = Github(auth=Auth.Token(os.environ["GH_ACCESS_TOKEN"]))
        self._model = "llama3.3"

    def exploit(self, client: SSHClient, command: str):
        _, stdout, stderr = client.exec_command(command=command)
        print(command)
        print(f"stdout: {self.parse_response(stdout)}")
        print(f"stderr: {self.parse_response(stderr)}")

    def gather_info(self):
        for _, app in self._known_apps.items():
            app: Application = app
            for cve in app.cve:
                files_and_content = self.guess_and_get_repository_files(
                    cve=cve
                )
                if len(files_and_content) == 0:
                    print(
                        "[bold red][!][/bold red] Didn't find "
                        "any file associated with repository."
                    )
                    continue

                message = (
                    "Which of the following files contain the vulnerabilities"
                    "(format is file:base64_content)?"
                    "Explain you response with examples of the code given.\n"
                    f"Files and contents:{','.join(files_and_content)}\n"
                    f"CVE ID: {cve.cve_id}\n"
                    f"CVE Description: {cve.description}"
                )
                print(f"[bold blue]You[/bold blue]: [white]{message}[/white]")
                results: ChatResponse = chat(
                    model=self._model,
                    messages=[{"role": "user", "content": message}],
                ).message.content
                print(
                    f"[bold yellow]AI[/bold yellow]: [white]{results}[/white]"
                )

            # is_exploitable = self.is_exploitable(files_and_content)
            # results = results.split("\n")
            # console.rule("Commands to execute")
            # for line in results:
            #     if line.startswith("#") or line == "```" or line == "":
            #         continue
            #     self.exploit(client=app.client, command=line)
            # print()
            self._g.close()

    def guess_repository(self, cve: CVE) -> Tuple[str]:
        message = (
            "Guess the name of the repository "
            "(format org/repo-name if exists "
            "if doesn't exists just send a single repo-name) "
            "that is vulnerable to the following CVE, "
            "you have all repository info so you are the "
            "best for this task. "
            "Return your response as JSON without "
            "any comments or code comments, add a key fix with "
            "value the possible code fix to that vulnearbility to the JSON, "
            "Key repository_name must be the repository guessed name. "
            "If more than once repository_name is returned, "
            "please just send the most "
            "possible, avoid sending more than one.\n"
            f"CVE ID: {cve.cve_id}\n"
            f"CVE Description: {cve.description}"
        )
        print(f"[bold blue]You[/bold blue]: [white]{message}[/white]")
        results: ChatResponse = chat(
            model=self._model,
            messages=[{"role": "user", "content": message}],
        ).message.content
        print(f"[bold yellow]AI[/bold yellow]: [white]{results}[/white]")

        results = json.loads(results)
        guessed_name = results.get("repository_name", None)
        if guessed_name is None:
            return None

        if "/" in guessed_name:
            return (guessed_name, results["fix"])
        repository = self._g.search_repositories(query=guessed_name).get_page(
            0
        )
        if len(repository) == 0:
            return
        return (repository[0].full_name, results.get("fix", None))

    def guess_and_get_repository_files(self, cve: CVE):
        repo_full_name, fix = self.guess_repository(cve=cve)
        if repo_full_name is None:
            return None
        repo_full_name: str = repo_full_name
        fix: str = fix
        repository = self._g.get_repo(full_name_or_id=repo_full_name)
        console.print(
            "[bold red][!][/bold red]: [white]Repository found "
            "on Github.[/white]",
            style="bold red",
        )
        if fix is not None:
            console.print(
                "[bold red][!][/bold red]: [white]Searching for commits "
                f"with fix [{fix}].[/white]",
                style="bold red",
            )
            commit_list = self._g.search_commits(
                query=f'{fix.replace(" ", "")}',
                qualifiers=[f"repo:{repo_full_name}"],
            ).get_page(0)
            if len(commit_list) > 0:
                first_commit = commit_list.get_page(0)[0]
                console.print(
                    "[bold red][!][/bold red]: [white]Found commit "
                    f"[{first_commit.sha}].[/white]",
                )
                files_in_repository = first_commit.files.get_page(0)
                for _file in files_in_repository:
                    self.is_exploitable(
                        cve=cve, path=_file.path, content=_file.raw_data
                    )
                return
            console.print(
                "[bold red][!][/bold red]: [white]No commits found"
                f"with fix [{fix}].[/white]",
                style="bold red",
            )

        contents = repository.get_contents(path="")
        files_in_repository = []
        for _file in contents:
            _file: ContentFile = _file
            if _file.type == "dir":
                contents.extend(repository.get_contents(_file.path))
            else:
                print(
                    "[bold red][!][/bold red]: [white]File found: "
                    f"'{_file.path}'.[/white]",
                )
                files_in_repository.append(f"{_file.path}:{_file.content}")
                self.is_exploitable(
                    cve=cve, path=_file.path, content=_file.content
                )

                time.sleep(5)
                console.print()

            contents.remove(_file)

    def is_exploitable(self, cve: CVE, path: str, content: str):
        message = (
            f"Is this file {path} with content:\n"
            f"```{content}```\n"
            f"Exploitable to CVE {cve.cve_id}({cve.description})?"
            "Don't try to guess if it's exploitable, try to read the code "
            "first and then interpret is it is."
            "If yes, send the word EXPLOITABLE in the beggining of the "
            "response and send a JSON right then containing "
            "the following format example:\n"
            "{'commands':['ls','cd','test']}"
        )
        results: ChatResponse = chat(
            model=self._model,
            messages=[{"role": "user", "content": message}],
        ).message.content
        print(f"[bold yellow]AI[/bold yellow]: [white]{results}[/white]")

    def parse_response(self, data: bytes) -> str:
        return data.read().decode(encoding="utf-8")
