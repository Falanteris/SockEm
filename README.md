# SockEm - A Live Connection Scanner  

![Build Status](https://github.com/Falanteris/SockEm/actions/workflows/ci.yaml/badge.svg)



SockEm is a tool for ...
## Features  

- Checks active connections and compare them to a neat **JSON ruleset**.  
- **Zero dependencies** – Works on any OS with Python 3 installed (no `pip` or external libraries required).
- **Optional save feature** - Save locally to a JSON file for further audit.

## What Does It Check?  

- **Live sockets** – Active network connections.  
- **Ports** – Open and listening ports.  
- **Processes** – Identifies processes associated with network activity.  

...And audits them against threat intelligence sources.  

## How to run
First, setup your ruleset, we will use PQL ( Process Query Language)

With PQL you are able to `Save`, `Report`, or `Kill` processes.

The Query itself has the following structure.

    <Kill/Save/Report> <ParentPID/*> <ProcessName/*> <Host/nonlocal> <Port/nsp>

**nsp** - Non Standard Port
**nonlocal** - any host that doesn't indicate local traffic.

Of course, you can stack multiple queries as well. The excerpt below is an example of that

        Save * * nonlocal *
        Kill * nc nonlocal *
        Kill * socat nonlocal *

This example would kill all processes exactly matching `nc` and `socat`, and 
`Save` all non-local traffic to a JSON file.

You can save this to a `search.pql` file in the same folder SockEm will run in.

Then Just

    python3 src/SockEm.py

Yep, it should run without a hitch.

Also if you don't want to clone the repo, that's alright too!


    curl https://raw.githubusercontent.com/Falanteris/SockEm/refs/heads/main/src/SockEm.py | python3

And now you can daemonize this process.

By setting DAEMONIZE env to 1

        PS

        $env:DAEMONIZE = 1

And for Linux

        Linux

        export DAEMONIZE = 1


## Concept

SockEm is designed to have zero write activity on the device to preserve forensic integrity.

You can create your own custom ruleset under the ruleset folder that can help you detect a specific event.

## Further Instructions

The `docs` section should attempt to further instruct you on how to install SockEm on your server/workstation.