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
<img width="1012" height="658" alt="image" src="https://github.com/user-attachments/assets/35d52d76-ac2d-4ac2-9f84-2bedd042d854" />

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

## Configuring the abuse.ch (MalwareBazaar) Heuristic

One of the client's heuristics checks each executable's SHA-256 hash against [MalwareBazaar](https://bazaar.abuse.ch/), a public database of known malware samples maintained by abuse.ch. This check requires a free API key.

### Getting an API key

1. Go to [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/) and create a free account.
2. Once logged in, navigate to your account profile to find your personal API key.

### Configuring the key

You have two options:

**Option A — Via the GUI (recommended):**
1. Launch the client.
2. Click the **Configuration** button in the toolbar.
3. Paste your API key into the *abuse.ch API Key* field and click **OK**.

The key is saved to `~/.up2date_config.json` and loaded automatically on every subsequent launch.

**Option B — Via environment variable:**

Set the `ABUSECH_API_KEY` environment variable before launching the client:

```powershell
# PowerShell
$env:ABUSECH_API_KEY = "your-api-key-here"
poetry run up2date_client
```

```cmd
:: Command Prompt
set ABUSECH_API_KEY=your-api-key-here
poetry run up2date_client
```

An environment variable set this way takes precedence over any key saved through the GUI.

If no key is configured, the heuristic is silently skipped and reported as *Unknown* in the results.

## Configuring the Gemini AI Integration

The client can send all available binary data (file info, community reviews, heuristic results) to Google's Gemini AI and display a brief safety verdict in the main table plus a detailed explanation in the *AI Analysis* tab.

### Getting a Gemini API key

1. Go to [Google AI Studio](https://aistudio.google.com/) and sign in with your Google account.
2. Click **Get API key** → **Create API key**.

### Configuring the key

**Option A — Via the GUI (recommended):**
1. Launch the client.
2. Click the **Configuration** button in the toolbar.
3. Paste your key into the *Gemini API Key* field and click **OK**.

The key is saved to `~/.up2date_config.json` and loaded automatically on every subsequent launch.

**Option B — Via environment variable:**

```powershell
# PowerShell
$env:GEMINI_API_KEY = "your-api-key-here"
poetry run up2date_client
```

```cmd
:: Command Prompt
set GEMINI_API_KEY=your-api-key-here
poetry run up2date_client
```

If no key is configured, the AI Suggestion column will remain blank and the AI Analysis tab will display a message indicating the key is missing.

## Unit Tests
To run unit tests, just `cd` into the specific folder (client or server) and run `poetry install`, then `poetry run pytest`.
