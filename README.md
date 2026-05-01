# up2date
Public, community-driven update transparency solution

# Usage
Simply docker-compose up the entire thing.

# Testing
Unit tests: cd into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.

## Server tests
To spin up the server locally, cd into the server folder and run `poetry intall`, then `poetry run pyton .\src\up2date_server\app.py`.
To run in hot reload mode, just set the environment variable `DEBUG` to `True`

# Client
The client is responsible for:
    - Monitoring new updates
    - Getting information from each executable
    - Communicating with the UP2DATE servers

# Server
The server is responsible for receiving data from users and replying to data queries.
It is basically an API implemented using Flask.
Merkle data is stored in a SQLite database, stored locally.
