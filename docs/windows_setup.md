
# Using SockEm to monitor Windows Machine

If you want to use SockEm to monitor endpoints, on Windows Machines, you can use *nssm*.

This tutorial will help you setup and connect SockEm into your Indexer ( *OpenSearch* or *ElasticSearch*)

In this example, my system is a x64 bit OS. Thus I used *nssm_64*. You can replace it with *nssm_32* if you're on a 32-bit system.

Download the *EXE* file from the latest release and the PQL file into one folder, the tree is going to look like this

```
    SockEm-windows.exe
    search.pql
```

NB: You can fetch the default ruleset from the main repository.

And then setup the nssm. If you're on a x64 bit system..
### Install the service 

```ps
& nssm_64.exe install SockEmService "$PWD\SockEm-windows.exe"

```


### Set environment variables

```ps
& nssm_64.exe set SockEmService AppEnvironmentExtra `
  "DAEMONIZE=1"
```
**IMPORTANT**: Running within nssm requires you to check the `Allow service to interact with desktop` to see full information of the process

Edit this with

    nssm_64.exe edit SockEmService

![alt text](image.png)

Check the box, and you're set.

### Start the service

```ps
& nssm_64.exe start SockEmService
```

### Optional: Writing stdout and stderr

SockEm outputs to stderr and stdout for debugging. If you wish to check the output logs, be it for troubleshooting or monitoring, you can set the nssm logging file.

```ps
 & nssm_64.exe set SockEmService AppStderr "$PWD\sockem-stderr.logs"

 & nssm_64.exe set SockEmService AppStdout "$PWD\sockem-stdout.logs"
```

