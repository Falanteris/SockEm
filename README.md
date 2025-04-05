# SockEm - A Live Connection Scanner  

## Features  

- Checks active connections against commonly used **Threat Hunting** knowledge bases.  
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

I encourage you to fork this repo and modify the CTI sources as needed. This project is meant to be as open-source and flexible as possible.

If you have any improvements, feel free to submit a PR/MR. Contributions are always welcome.