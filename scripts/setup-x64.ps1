# Prompt user for environment variables
$indexerUsername = Read-Host "Enter INDEXER_USERNAME"
$indexerPassword = Read-Host "Enter INDEXER_PASSWORD (will be stored as plain text)"
$indexerHost     = Read-Host "Enter INDEXER_HOST (e.g., http://localhost)"
$indexerPort     = Read-Host "Enter INDEXER_PORT (e.g., 9200)"
$shufflerWebhookURL    = Read-Host "Enter SHUFFLER_WEBHOOK_URL (e.g., http://localhost)"
$shufflerNotifySeverity    = Read-Host "Enter NOTIFY_LEVEL (e.g., MEDIUM)"
# Set paths
$installPath = $PWD.path
$sockemExe   = "$installPath\SockEm-windows.exe"
$nssmExe     = "nssm_64.exe"
$svcName     = "SockEmService"

if (-Not (Test-Path $nssmExe)) {
    Write-Error "❌ NSSM executable '$nssmExe' not found in current directory."
    exit 1
}

$existing = sc.exe query $svcName 2>&1 | Select-String "SERVICE_NAME"
if ($existing) {
    Write-Warning "⚠️ Service '$svcName' already exists. Skipping installation."
    exit 1
}

# Install the service
& $nssmExe install $svcName $sockemExe

# Set working directory
& $nssmExe set $svcName AppDirectory "$installPath"

# Set environment variables
& $nssmExe set $svcName AppEnvironmentExtra `
    "INDEXER_USERNAME=$indexerUsername" `
    "INDEXER_PASSWORD=$indexerPassword" `
    "INDEXER_HOST=$indexerHost" `
    "INDEXER_PORT=$indexerPort" `
    "SHUFFLER_WEBHOOK_URL=$shufflerWebhookURL" `
    "NOTIFY_LEVEL=$shufflerNotifySeverity" `
    "DAEMONIZE=1"

# Start the service
Write-Host "`nConfiguration complete. Start service now? (Y/n): "

$confirm = Read-Host

if ($confirm -ne 'n' -and $confirm -ne 'N') {
    & $nssmExe start $svcName
    Write-Host "✅ SockEmService has been installed and started."
} else {
    Write-Host "❗ Service installation complete, but not started."
}

Write-Host "✅ SockEmService has been installed and started."
