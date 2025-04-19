
### Configuring SockEm to Connect to the Indexer

To configure SockEm to connect to the Indexer, follow these steps:

1. **Set Up Environment Variables**:
Ensure the following environment variables are set in your system 
- `INDEXER_HOST`: The hostname or IP address of the Indexer service.
- `INDEXER_PORT`: The port number on which the Indexer is running.
- `INDEXER_USERNAME`: The username for authentication 
- `INDEXER_PASSWORD`: The password for authentication 

2. **Create a Systemd Service File**:
    If you're using a Linux system with systemd, you can create a service file to manage SockEm as a daemon. Here's an example:

    ```ini
    [Unit]
    Description=SockEm Service
    After=network.target

    [Service]
    Environment="INDEXER_HOST=your-indexer-host"
    Environment="INDEXER_PORT=your-indexer-port"
    Environment="INDEXER_USERNAME=your-username"
    Environment="INDEXER_PASSWORD=your-password"
    Environment="DAEMONIZE=1"
    WorkingDirectory=/path/to/sockem
    ExecStart=/usr/bin/python3 src/SockEm.py
    Restart=always
    User=root

    [Install]
    WantedBy=multi-user.target
    ```

    Replace the placeholders with your actual configuration values. Save this file as `/etc/systemd/system/sockem.service`.

3. **Enable and Start the Service**:
    Run the following commands to enable and start the service:
    ```bash
    sudo systemctl enable sockem.service
    sudo systemctl start sockem.service
    ```


