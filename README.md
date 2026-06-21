# UP2DATE
Up2Date is a public, community-driven update transparency solution.

It allows you to publish and retrieve information about existing software versions in your machine, and automatically looks for signs of malicious or broken updates.

<img width="1095" height="725" alt="image" src="https://github.com/user-attachments/assets/e469b1e7-52d9-45dd-9224-e20ccbe3af24" />

## In plain english, please?
Your printer's client auto-updated from v7.5.123 to v7.6.1 when you weren't looking.
Is this new version safe? Is it good? Does it still support your old printer? 

Up2Date helps you to detect these changes and answer these questions through:

1 - Continuously monitoring your machine for all launched software and notifying you.

2 - The power of community: you can see what other users with that same version are saying about it, or submit your own review.

3 - A set of pre-packaged heuristics that run locally and can detect signs of a malicious update, such as a Freeze Attack, a Replay attack, or a targeted malicious version against you.


If you're not very technical, don't worry - it also comes with an AI integration to parse all this nerdy mumbojumbo and let you know if you should run the new version or not.

# General Architecture
Up2Date is composed of two programs:

## Client
The client is responsible for running localy on each user's machine and:
* Monitoring running executables
* Facilitating the communication with UP2DATE servers (e.g., uploading new reviews, seeing existing reviews, gathering data, etc.)
* Running heuristics to detect signs of malicious updates

If supplied with an anthropic API key, it can also use external AI models through a custom harness to generate suggestions regarding each executable's safety.

## Server
The server is responsible for receiving data from users and replying to data queries.
It is basically an API implemented using Flask.
Merkle data is stored in multiple SQLite databases, stored locally.

A more complete view is seen below:
<img width="911" height="839" alt="image" src="https://github.com/user-attachments/assets/05b340e9-4f58-4f9b-8376-c91d22c9c7b9" />

# Running Up2Date
This is a PoC version. It comes with a client and a server. It only runs on the Windows operating system.
To test it, you must spin up both programs. By default, it is configured to run in the same machine, but of course you can run the server separately as well. More information below.

You must have `poetry` installed in your machine.
If you do not have poetry, follow the official installation instructions here: https://python-poetry.org/docs/

## Running the Server
To spin up the server locally, cd into the server folder and run `poetry install`, then `poetry run up2date_server`.
To run in hot reload mode, just set the environment variable `DEBUG` to `True`.

A set of test data is included with this repository under `up2date_server/merkle_data/`. It is used automatically.
If you want to start with a fresh database, simply delete the files in that folder (but not the folder itself).

## Running the Client
To run the client, cd into the client folder and run `poetry install`, then `poetry run up2date_client`
Note: you may have to install PyQt5 manually: `poetry run pip install pyqt5`, `poetry run pip install pyqt5-qt5`
By default, the client queries the server at `http://localhost:5000`. To change this, set the `SERVER_URL` environment variable to whatever you want.

## Unit Tests
To run unit tests, just `cd` into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.
