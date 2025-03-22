from ares.utils.connection import Connection
from ares.utils.cve import OpenCVEContext


def main():
    # Establish connection.
    connection = Connection()
    connection.extract_applications()
    known_apps = connection.known_apps
    # Retrieve information about public exploits.
    search_sploit_context = OpenCVEContext(know_apps=known_apps)
    search_sploit_context.retrieve_cve()
    # Ask AI for commands to exploit them.
    ...
    # If success then return, 
    # else throw exception and exit.
    #success()
    ...

if __name__ == "__main__":
    main()