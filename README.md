

# fabular

[![Build Status](https://travis-ci.com/phdenzel/fabular.svg?token=StKyxTumiWU6dwAxmZqF&branch=master)](https://travis-ci.com/phdenzel/fabular)

A command-line chat app for secure communication between you and your friends!

Key features:

-   hybrid encryption scheme for connection handshake
-   session-randomized Fernet (AES-128-CBC) encryption for all messages
-   username-specific colors


## Requirements

-   `python3`
-   `pipenv` (for dev features)
-   a server with an open port
-   at least two command-line machines to chat


## Install

Simply type `pip install fabular`.

To install from source, you may type `make prereq && make dev`, which
installs `pipenv` and executes

    pipenv install --dev
    pipenv install -e .


## Usage

For more information type

    [pipenv run] fabular -h

Run fabular in server-mode (set up a fabular server for clients to connect to):

    [pipenv run] fabular -s --host 127.0.0.1 --port 50120

Run fabular in client-mode (connecting to a chat server):

    [pipenv run] fabular -c --host 127.0.0.1 --port 50120

Run fabular in test-mode:

    [pipenv run] fabular -t

or with `pytest`:

    [pipenv run] pytest -v --cov=fabular --cov-report=html

