# Using SockEm to monitor Linux Machine

If you're using a Linux system with systemd, you can create a service file to manage SockEm as a daemon. Here's an example:

This tutorial will help you setup and connect SockEm into your Indexer ( *OpenSearch* or *ElasticSearch*)

### Create a Systemd Service File

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


