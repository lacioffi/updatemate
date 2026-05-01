# up2date
Public, community-driven update transparency solution

# Usage
Simply docker-compose up the entire thing.

Alternatively, you can spin up the server and the client individually. See text below for more info.

# Testing
Unit tests: cd into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.

## Server tests
To spin up the server locally, cd into the server folder and run `poetry install`, then `poetry run up2date_server`.
To run in hot reload mode, just set the environment variable `DEBUG` to `True`

## Client tests
To run the client, cd into the client folder and run `poetry install`, then `poetry run up2date_client`
Note: you may have to install PyQt5 manually: `poetry run pip install pyqt5`, `poetry run pip install pyqt5-qt5`

# General architecture
## Client
The client is responsible for:
    - Monitoring new updates
    - Getting information from each executable
    - Communicating with the UP2DATE servers

## Server
The server is responsible for receiving data from users and replying to data queries.
It is basically an API implemented using Flask.
Merkle data is stored in a SQLite database, stored locally.
