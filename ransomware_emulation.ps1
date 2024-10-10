# Check if the script is running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as administrator, re-run the script with elevated privileges
if (-not (Test-Administrator)) {
    Write-Host "This script must be run as an administrator."
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define directories to simulate ransomware/malware activity
$targetDirs = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Videos",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Roaming",    
    "$env:USERPROFILE\AppData\LocalLow",    
    "$env:USERPROFILE\AppData\Local",       
    "C:\Windows\Temp",
    "C:\ProgramData",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\Tasks",
    "C:\Users\Public",
    "C:\Windows\Inf",
    "C:\Windows\Fonts"
)

# Define the maximum number of files to create
$maxFiles = 60

# Function to generate a random three-character extension
function Get-RandomExtension {
    $characters = "abcdefghijklmnopqrstuvwxyz"
    return -join ((Get-Random -InputObject $characters.ToCharArray() -Count 3))
}

# Function to generate a random file name with a maximum of 10 characters
function Get-RandomFileName {
    $characters = "abcdefghijklmnopqrstuvwxyz"
    return -join ((Get-Random -InputObject $characters.ToCharArray() -Count (Get-Random -Minimum 5 -Maximum 10)))
}

# Function to create random files with a maximum size of 1 KB
function Create-RandomFile {
    param (
        [string]$directory
    )
    # Generate a random file name with a maximum of 10 characters
    $fileName = Get-RandomFileName

    # Create a random extension with exactly 3 characters
    $randomExtension = Get-RandomExtension

    # Full path of the file
    $filePath = "$directory\$fileName.$randomExtension"

    # Randomly decide if the file should contain content or be empty
    if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) {
        # Create an empty file
        New-Item -Path $filePath -ItemType File -Force | Out-Null
    } else {
        # Create a file with random content, max size 1 KB (1024 bytes)
        $randomBytes = New-Object Byte[] (Get-Random -Minimum 10 -Maximum 1024) # Random size between 10 and 1024 bytes
        [void] (Get-Random).NextBytes($randomBytes)
        [System.IO.File]::WriteAllBytes($filePath, $randomBytes)
    }

    Write-Host "Created file: $filePath"
    return $filePath
}

# Function to create files in ransom_emulation folder
function Create-Files {
    $folderPath = ".\ransom_emulation"
    
    # Check if the folder exists
    if (Test-Path -Path $folderPath) {
        Write-Host "The folder 'ransom_emulation' and files already exist. No new files created." -ForegroundColor Yellow
    } else {
        # Create the folder
        New-Item -Path $folderPath -ItemType Directory -Force | Out-Null

        # Create 10 text files with 5 lines of Lorem Ipsum
        for ($i = 1; $i -le 10; $i++) {
            $filePath = "$folderPath\file$i.txt"
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit." * 5 | Out-File -FilePath $filePath -Force
        }

        Write-Host "Files created successfully!" -ForegroundColor Green
    }
}

# Function to encrypt files
function Encrypt-Files {
    $folderPath = ".\ransom_emulation"
    $keyString = "VerySecureEncryptionKey12345"  # Hardcoded AES key (can be adjusted)
    $key = [System.Text.Encoding]::UTF8.GetBytes($keyString.PadRight(32, '0')) # Ensure key is 32 bytes for AES-256
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Key = $key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()  # Random IV for each session
    
    # Check if the folder exists
    if (-not (Test-Path -Path $folderPath)) {
        Write-Host "Folder 'ransom_emulation' does not exist. Create the files first." -ForegroundColor Red
        return
    }
    
    # Encrypt each file in the folder
    Get-ChildItem $folderPath -Filter "*.txt" | ForEach-Object {
        $filePath = $_.FullName
        $fileContent = Get-Content -Path $filePath -Raw

        $encryptor = $aes.CreateEncryptor()
        $fileBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
        $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)

        # Write the encrypted content back to the file
        [System.IO.File]::WriteAllBytes($filePath, $encryptedBytes)

        Write-Host "$($_.Name) encrypted successfully!" -ForegroundColor Green
    }
    
    # Save the IV to a file (so decryption can be possible)
    $ivFile = "$folderPath\iv.bin"
    [System.IO.File]::WriteAllBytes($ivFile, $aes.IV)

    Write-Host "All files encrypted and IV saved to iv.bin." -ForegroundColor Green
}

# Function to remove simulation files
function Remove-SimulationFiles {
    param (
        [array]$files
    )
    foreach ($file in $files) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force
            Write-Host "Removed file: $file"
        } else {
            Write-Host "File not found: $file"
        }
    }
}

# Function to delete files and folder
function Delete-Files {
    $folderPath = ".\ransom_emulation"
    $logFilePath = "C:\Windows\Temp\RansomwareSimulationLog.txt"

    # Check if the log file exists and remove the random extension files
    if (Test-Path -Path $logFilePath) {
        $createdFiles = Get-Content -Path $logFilePath
        Remove-SimulationFiles -files $createdFiles
        # Clear the log file after removing files
        Clear-Content -Path $logFilePath
        # Remove the log file itself
        Remove-Item -Path $logFilePath -Force
        Write-Host "All random extension files have been removed from the log." -ForegroundColor Green
    } else {
        Write-Host "No log file found for random extension files. Nothing to delete." -ForegroundColor Yellow
    }

    # Check if the folder exists and remove it
    if (Test-Path -Path $folderPath) {
        Remove-Item -Path $folderPath -Recurse -Force
        Write-Host "All files and the 'ransom_emulation' folder deleted." -ForegroundColor Green
    } else {
        Write-Host "Folder 'ransom_emulation' does not exist. Nothing to delete." -ForegroundColor Yellow
    }
}

# Log file path
$logFilePath = "C:\Windows\Temp\RansomwareSimulationLog.txt"

# Main menu for action selection
function Main-Menu {
    while ($true) {
        Write-Host "`nPlease choose an option:"
        Write-Host "1. Create random extension files"
        Write-Host "2. Create files in ransom_emulation folder"
        Write-Host "3. Encrypt files"
        Write-Host "4. Delete files"
        Write-Host "5. Exit"
        $choice = Read-Host "Enter your choice (1, 2, 3, 4 or 5)"

        switch ($choice) {
            1 {
                Write-Host "Starting random file creation..."
                $createdFiles = @()
                for ($i = 0; $i -lt $maxFiles; $i++) {
                    # Pick a random directory
                    $randomDir = Get-Random -InputObject $targetDirs
                    # Create the random file in the chosen directory
                    $filePath = Create-RandomFile -directory $randomDir
                    $createdFiles += $filePath
                    # Append the created file path to the log file
                    $filePath | Out-File -FilePath $logFilePath -Encoding UTF8 -Append
                }
                Write-Host "Random file creation completed. $maxFiles files created."
                Write-Host "Log of created files saved to: $logFilePath"
            }
            2 {
                Create-Files
            }
            3 {
                Encrypt-Files
            }
            4 {
                Delete-Files
            }
            5 {
                Write-Host "Exiting script." -ForegroundColor Cyan
                exit
            }
            default {
                Write-Host "Invalid option. Please choose again." -ForegroundColor Red
            }
        }
    }
}

# Run the main menu function once at the start
Main-Menu
