## Configuring `ti_data/config.json`

1. Create the `ti_data` folder

        mkdir -p ti_data

2. Open the `ti_data/config.json` file in a text editor.
3. The TI data should be structured as an **array of JSON objects**, each containing the following fields:

    - **source**: The name of the data source.
    - **type**: The type of threat intelligence data.
    - **description**: A brief description of the data.

**Example:**
```json
[
    {
        "source":"https://blocklist.greensnow.co/greensnow.txt",
        "type":"freetext",
        "description":"GreenSnow Blocklist"
    },
    {
        "source":"https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type":"csv",
        "description":"Feodo Tracker Blocklist"
    },
    {
        "source":"https://malsilo.gitlab.io/feeds/dumps/ip_list.txt",
        "type":"csv",
        "description":"Malsilo Blocklist"
    }
]
```

With this, you can enhance SockEm's detection with your curated Threat Intelligence sources.

As of the time of writing ( August 15th, 2025). This feature does not support TI that requires Authentication yet.