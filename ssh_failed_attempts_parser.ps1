# SSH Failed Attempts Parser (PowerShell Version)
# This script parses various log files for failed SSH login attempts
# Supports multiple log formats and provides detailed reporting

param(
    [Parameter(Position=0)]
    [string[]]$LogFiles = @(),
    
    [Parameter()]
    [string]$OutputFile = "",
    
    [Parameter()]
    [switch]$Verbose,
    
    [Parameter()]
    [switch]$SummaryOnly,
    
    [Parameter()]
    [string]$FromDate = "",
    
    [Parameter()]
    [string]$ToDate = "",
    
    [Parameter()]
    [string]$WhitelistFile = "",
    
    [Parameter()]
    [switch]$AuthLog,
    
    [Parameter()]
    [switch]$Messages,
    
    [Parameter()]
    [switch]$Secure,
    
    [Parameter()]
    [switch]$Help
)

# Function to display usage
function Show-Usage {
    Write-Host @"
Usage: .\ssh_failed_attempts_parser.ps1 [OPTIONS] [LOG_FILES...]

Parse SSH log files for failed login attempts.

OPTIONS:
    -LogFiles <files>         Specify log files to parse
    -OutputFile <file>        Output results to file (default: stdout)
    -Verbose                  Enable verbose output
    -SummaryOnly              Show summary only
    -FromDate <date>          Filter from date (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    -ToDate <date>            Filter to date (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    -WhitelistFile <file>     File containing IP addresses to whitelist (one per line)
    -AuthLog                  Parse /var/log/auth.log (default SSH log location)
    -Messages                 Parse /var/log/messages
    -Secure                   Parse /var/log/secure
    -Help                     Show this help message

EXAMPLES:
    .\ssh_failed_attempts_parser.ps1 sample_auth.log
    .\ssh_failed_attempts_parser.ps1 -OutputFile failed_ssh.txt sample_auth.log
    .\ssh_failed_attempts_parser.ps1 -FromDate "2024-01-01" -ToDate "2024-01-31" sample_auth.log
    .\ssh_failed_attempts_parser.ps1 -Verbose -WhitelistFile whitelist.txt sample_auth.log

"@
}

# Function to print colored output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

# Function to convert date to timestamp
function Convert-DateToTimestamp {
    param([string]$DateStr)
    
    if ($DateStr -match '^\d{4}-\d{2}-\d{2}$') {
        # Date only, add time
        $DateStr = "$DateStr 00:00:00"
    }
    
    try {
        $date = [DateTime]::ParseExact($DateStr, "yyyy-MM-dd HH:mm:ss", $null)
        return $date.Ticks
    }
    catch {
        return 0
    }
}

# Function to check if IP is whitelisted
function Test-WhitelistedIP {
    param([string]$IP, [string]$WhitelistFile)
    
    if ([string]::IsNullOrEmpty($WhitelistFile)) {
        return $false
    }
    
    if (Test-Path $WhitelistFile) {
        $whitelist = Get-Content $WhitelistFile
        return $whitelist -contains $IP
    }
    
    return $false
}

# Function to parse log file
function Parse-LogFile {
    param(
        [string]$LogFile,
        [string]$FromDate,
        [string]$ToDate,
        [string]$WhitelistFile,
        [bool]$SummaryOnly
    )
    
    Write-Info "Parsing $LogFile..."
    
    # Check if file exists and is readable
    if (-not (Test-Path $LogFile)) {
        Write-Error "Log file $LogFile does not exist"
        return @()
    }
    
    $failedAttempts = @()
    
    # Read the log file
    $lines = Get-Content $LogFile -ErrorAction SilentlyContinue
    
    if (-not $lines) {
        Write-Warning "No failed SSH attempts found in $LogFile"
        return @()
    }
    
    # Process each line
    foreach ($line in $lines) {
        # Check for failed SSH patterns
        if ($line -match "(Failed password|Invalid user|Connection closed by invalid user|PAM authentication failure|Failed keyboard-interactive)") {
            
            # Extract timestamp
            $timestamp = ""
            if ($line -match '^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})') {
                $timestamp = $matches[1]
            }
            elseif ($line -match '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})') {
                $timestamp = $matches[1]
            }
            
            # Extract IP address
            $ip = ""
            if ($line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $ip = $matches[1]
            }
            
            # Extract username
            $user = ""
            if ($line -match 'Failed password for ([^ ]+)') {
                $user = $matches[1]
            }
            elseif ($line -match 'Invalid user ([^ ]+)') {
                $user = $matches[1]
            }
            
            # Extract message
            $message = $line -replace '^[^:]*:[^:]*:[^:]*:[^:]* ', ''
            
            # Apply date filters if specified
            if (-not [string]::IsNullOrEmpty($FromDate) -or -not [string]::IsNullOrEmpty($ToDate)) {
                $lineTimestamp = Convert-DateToTimestamp $timestamp
                
                if (-not [string]::IsNullOrEmpty($FromDate)) {
                    $fromTimestamp = Convert-DateToTimestamp $FromDate
                    if ($lineTimestamp -lt $fromTimestamp) {
                        continue
                    }
                }
                
                if (-not [string]::IsNullOrEmpty($ToDate)) {
                    $toTimestamp = Convert-DateToTimestamp $ToDate
                    if ($lineTimestamp -gt $toTimestamp) {
                        continue
                    }
                }
            }
            
            # Skip whitelisted IPs
            if (Test-WhitelistedIP -IP $ip -WhitelistFile $WhitelistFile) {
                continue
            }
            
            # Create attempt object
            $attempt = [PSCustomObject]@{
                Timestamp = $timestamp
                IP = $ip
                User = $user
                Message = $message
            }
            
            $failedAttempts += $attempt
        }
    }
    
    return $failedAttempts
}

# Function to generate summary
function Generate-Summary {
    param([array]$AllAttempts)
    
    if ($AllAttempts.Count -eq 0) {
        Write-Warning "No failed SSH attempts found in any log files"
        return
    }
    
    Write-Info "Generating summary..."
    
    # Count total attempts
    $totalAttempts = $AllAttempts.Count
    
    # Count unique IPs
    $uniqueIPs = ($AllAttempts.IP | Sort-Object -Unique).Count
    
    # Count unique users
    $uniqueUsers = ($AllAttempts.User | Sort-Object -Unique).Count
    
    # Top attacking IPs
    Write-Host "=== SSH FAILED ATTEMPTS SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total failed attempts: $totalAttempts"
    Write-Host "Unique attacking IPs: $uniqueIPs"
    Write-Host "Unique usernames targeted: $uniqueUsers"
    Write-Host ""
    
    Write-Host "=== TOP 10 ATTACKING IP ADDRESSES ===" -ForegroundColor Cyan
    $AllAttempts.IP | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "$($_.Count) attempts from $($_.Name)"
    }
    Write-Host ""
    
    Write-Host "=== TOP 10 TARGETED USERNAMES ===" -ForegroundColor Cyan
    $AllAttempts.User | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "$($_.Count) attempts for user '$($_.Name)'"
    }
    Write-Host ""
    
    Write-Host "=== RECENT ATTEMPTS (Last 10) ===" -ForegroundColor Cyan
    $AllAttempts | Select-Object -Last 10 | ForEach-Object {
        Write-Host "$($_.Timestamp) - $($_.IP) tried to access '$($_.User)'"
    }
}

# Main execution
function Main {
    # Show help if requested
    if ($Help) {
        Show-Usage
        return
    }
    
    # Add default log files if specified
    if ($AuthLog) {
        $LogFiles += "/var/log/auth.log"
    }
    if ($Messages) {
        $LogFiles += "/var/log/messages"
    }
    if ($Secure) {
        $LogFiles += "/var/log/secure"
    }
    
    # Check if we have any log files
    if ($LogFiles.Count -eq 0) {
        # Default to auth.log if no files specified
        if (Test-Path "/var/log/auth.log") {
            $LogFiles += "/var/log/auth.log"
            Write-Info "Using default log file: /var/log/auth.log"
        }
        else {
            Write-Error "No log files specified and no default auth.log found"
            Show-Usage
            return
        }
    }
    
    # Validate whitelist file if specified
    if (-not [string]::IsNullOrEmpty($WhitelistFile) -and -not (Test-Path $WhitelistFile)) {
        Write-Error "Whitelist file $WhitelistFile does not exist"
        return
    }
    
    Write-Info "Starting SSH failed attempts parser..."
    Write-Info "Log files to process: $($LogFiles -join ', ')"
    
    if (-not [string]::IsNullOrEmpty($FromDate)) {
        Write-Info "Filtering from date: $FromDate"
    }
    
    if (-not [string]::IsNullOrEmpty($ToDate)) {
        Write-Info "Filtering to date: $ToDate"
    }
    
    if (-not [string]::IsNullOrEmpty($WhitelistFile)) {
        Write-Info "Using IP whitelist: $WhitelistFile"
    }
    
    # Redirect output if specified
    if (-not [string]::IsNullOrEmpty($OutputFile)) {
        Write-Info "Output will be saved to: $OutputFile"
    }
    
    # Collect all attempts
    $allAttempts = @()
    
    foreach ($logFile in $LogFiles) {
        $attempts = Parse-LogFile -LogFile $logFile -FromDate $FromDate -ToDate $ToDate -WhitelistFile $WhitelistFile -SummaryOnly $SummaryOnly
        $allAttempts += $attempts
    }
    
    # Generate output
    if ($SummaryOnly) {
        Generate-Summary -AllAttempts $allAttempts
    }
    else {
        foreach ($attempt in $allAttempts) {
            Write-Host "Timestamp: $($attempt.Timestamp)"
            Write-Host "IP Address: $($attempt.IP)"
            Write-Host "Username: $($attempt.User)"
            Write-Host "Message: $($attempt.Message)"
            Write-Host "---"
        }
    }
    
    Write-Success "Parsing completed successfully"
}

# Run main function
Main 