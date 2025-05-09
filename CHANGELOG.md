# CHANGELOG

## [2025-09-05]
- SockEm is now able to send data to Shuffler.
    - Examples can be found in the `soar_examples` folder.
    - Configuration for the integration is located in the `shuffler` folder.
        - Users need to download the `shuffler` folder to start sending SockEm data to Shuffler.
- Quality of Life (QOL) environment variables have been added to enhance integration retries:
    - `SHUFFLE_URL`: WebHook URL
    - `NOTIFY_LEVEL`: Alerts with this vulnerability or higher will be sent to shuffler.
    - These parameters can be configured via Environment Variables.