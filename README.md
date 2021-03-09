
# Table of Contents

1.  [fabular](#orgf00e76a)
    1.  [Requirements](#org2e4eb1f)
    2.  [Install](#org3017799)
    3.  [Usage](#org15bea3f)


<a id="orgf00e76a"></a>

# fabular

 <!-- [https://travis-ci.com/phdenzel/fabular.svg?token=StKyxTumiWU6dwAxmZqF&branch=master](https://travis-ci.com/phdenzel/fabular) -->
[![Build Status](https://travis-ci.com/phdenzel/fabular.svg?token=StKyxTumiWU6dwAxmZqF&branch=master)](https://travis-ci.com/phdenzel/fabular)

A command-line chat app for secure communication between you and your friends!

Key features:

-   hybrid encryption scheme to establish a connection
-   session-randomized AES (Rijndael) encryption in EAX mode for messages
-   username-specific colors


<a id="org2e4eb1f"></a>

## Requirements

-   `python3`
-   `pipenv`
-   a server with an open port
-   at least two command-line machines to chat


<a id="org3017799"></a>

## Install

Simply type `pip install fabular`.

To install from source, you may type

    pipenv install --dev
    pipenv install -e .


<a id="org15bea3f"></a>

## Usage

Run fabular in server-mode (set up a fabular server for clients to connect to):

    [pipenv run] fabular -s $*

Run fabular in client-mode (connecting to a chat server):

    [pipenv run] fabular -c $*

Run fabular in test-mode:

    [pipenv run] fabular -t

or with `pytest`:

    [pipenv run] pytest -v --cov=fabular --cov-report=html

