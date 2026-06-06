# UP2DATE
Up2Date is a public, community-driven update transparency solution.

<img width="1095" height="725" alt="image" src="https://github.com/user-attachments/assets/e469b1e7-52d9-45dd-9224-e20ccbe3af24" />

## In plain english, please?
Up2Date allows you to publish and retrieve information about existing software versions. It also comes pre-packaged with a set of heuristics that run locally and can detect signs of a malicious update, such as a Freeze Attack, a Replay attack, a targeted malicious version

# General Architecture
Up2Date is composed of two programs:

## Client
The client is responsible for running localy on each user's machine and:
* Monitoring running executables
* Facilitating the communication with UP2DATE servers
* Running heuristics to detect signs of malicious updates

## Server
The server is responsible for receiving data from users and replying to data queries.
It is basically an API implemented using Flask.
Merkle data is stored in multiple SQLite databases, stored locally.

A more complete view is seen below:
<img width="911" height="839" alt="image" src="https://github.com/user-attachments/assets/05b340e9-4f58-4f9b-8376-c91d22c9c7b9" />

# Running Up2Date
This is a PoC version. It comes with a client and a server.
To test it, you must spin up both programs. By default, it is configured to run in the same machine, but of course you can run the server separately as well. More information below.

## Running the Server
To spin up the server locally, cd into the server folder and run `poetry install`, then `poetry run up2date_server`.
To run in hot reload mode, just set the environment variable `DEBUG` to `True`

## Running the Client
To run the client, cd into the client folder and run `poetry install`, then `poetry run up2date_client`
Note: you may have to install PyQt5 manually: `poetry run pip install pyqt5`, `poetry run pip install pyqt5-qt5`
By default, the client queries the server at `http://localhost:5000`. To change this, set the `SERVER_URL` environment variable to whatever you want.

## Unit Tests
To run unit tests, just `cd` into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.
