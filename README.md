# up2date
Public, community-driven update transparency solution

# Usage
Simply docker-compose up the entire thing.

For tests, cd into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.

# Client
The client is responsible for:
    - Monitoring new updates
    - Getting information from each executable
    - Communicating with the UP2DATE servers

# Server
