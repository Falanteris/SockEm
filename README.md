# SockEm - A Live Connection Scanner  

## Features  

- Checks active connections and compare them to a neat **JSON ruleset**.  
- **Zero dependencies** – Works on any OS with Python 3 installed (no `pip` or external libraries required).  
- **Forensic-friendly** – Leaves no trace; all outputs are sent directly to `stdout`. (Use output redirection if you need to save results.)  

## What Does It Check?  

- **Live sockets** – Active network connections.  
- **Ports** – Open and listening ports.  
- **Processes** – Identifies processes associated with network activity.  

...And audits them against threat intelligence sources.  

## How to run

Just

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