#!/bin/bash

# SSH Failed Attempts Parser
# This script parses various log files for failed SSH login attempts
# Supports multiple log formats and provides detailed reporting

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
LOG_FILES=()
OUTPUT_FILE=""
VERBOSE=false
SUMMARY_ONLY=false
FROM_DATE=""
TO_DATE=""
IP_WHITELIST=""

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [LOG_FILES...]

Parse SSH log files for failed login attempts.

OPTIONS:
    -h, --help              Show this help message
    -o, --output FILE       Output results to FILE (default: stdout)
    -v, --verbose           Enable verbose output
    -s, --summary           Show summary only
    -f, --from-date DATE    Filter from DATE (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    -t, --to-date DATE      Filter to DATE (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    -w, --whitelist FILE    File containing IP addresses to whitelist (one per line)
    -a, --auth-log          Parse /var/log/auth.log (default SSH log location)
    -m, --messages          Parse /var/log/messages
    -s, --secure            Parse /var/log/secure

EXAMPLES:
    $0 /var/log/auth.log
    $0 -o failed_ssh.txt /var/log/auth.log /var/log/secure
    $0 -f "2024-01-01" -t "2024-01-31" /var/log/auth.log
    $0 -v -w whitelist.txt /var/log/auth.log

EOF
}

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to convert date to timestamp
date_to_timestamp() {
    local date_str="$1"
    if [[ $date_str =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        # Date only, add time
        date_str="${date_str} 00:00:00"
    fi
    date -d "$date_str" +%s 2>/dev/null || echo "0"
}

# Function to check if IP is whitelisted
is_whitelisted() {
    local ip="$1"
    if [[ -z "$IP_WHITELIST" ]]; then
        return 1
    fi
    grep -q "^${ip}$" "$IP_WHITELIST" 2>/dev/null
}

# Function to parse log file
parse_log_file() {
    local log_file="$1"
    local temp_file=$(mktemp)
    
    print_info "Parsing $log_file..."
    
    # Check if file exists and is readable
    if [[ ! -f "$log_file" ]]; then
        print_error "Log file $log_file does not exist"
        return 1
    fi
    
    if [[ ! -r "$log_file" ]]; then
        print_error "Log file $log_file is not readable"
        return 1
    fi
    
    # Extract failed SSH attempts with different patterns
    # Pattern 1: Failed password for user
    # Pattern 2: Invalid user
    # Pattern 3: Connection closed by invalid user
    # Pattern 4: PAM authentication failure
    # Pattern 5: Failed keyboard-interactive/pam
    
    grep -E "(Failed password|Invalid user|Connection closed by invalid user|PAM authentication failure|Failed keyboard-interactive)" "$log_file" > "$temp_file" 2>/dev/null || true
    
    if [[ ! -s "$temp_file" ]]; then
        print_warning "No failed SSH attempts found in $log_file"
        rm -f "$temp_file"
        return 0
    fi
    
    # Process each line
    while IFS= read -r line; do
        # Extract timestamp, IP, user, and other relevant info
        local timestamp=""
        local ip=""
        local user=""
        local message=""
        
        # Try different log formats
        if [[ $line =~ ^([A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
            # Format: Jan 1 12:00:00
            timestamp=$(echo "$line" | grep -oE '^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}')
        elif [[ $line =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
            # Format: 2024-01-01T12:00:00
            timestamp=$(echo "$line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}')
        fi
        
        # Extract IP address
        ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        
        # Extract username
        if [[ $line =~ "Failed password for" ]]; then
            user=$(echo "$line" | grep -oE 'Failed password for [^ ]+' | awk '{print $4}')
        elif [[ $line =~ "Invalid user" ]]; then
            user=$(echo "$line" | grep -oE 'Invalid user [^ ]+' | awk '{print $3}')
        fi
        
        # Extract message
        message=$(echo "$line" | sed 's/^[^:]*:[^:]*:[^:]*:[^:]* //')
        
        # Apply date filters if specified
        if [[ -n "$FROM_DATE" || -n "$TO_DATE" ]]; then
            local line_timestamp=$(date_to_timestamp "$timestamp")
            if [[ -n "$FROM_DATE" && $line_timestamp -lt $(date_to_timestamp "$FROM_DATE") ]]; then
                continue
            fi
            if [[ -n "$TO_DATE" && $line_timestamp -gt $(date_to_timestamp "$TO_DATE") ]]; then
                continue
            fi
        fi
        
        # Skip whitelisted IPs
        if is_whitelisted "$ip"; then
            continue
        fi
        
        # Output the parsed information
        if [[ "$SUMMARY_ONLY" == "true" ]]; then
            echo "$timestamp|$ip|$user|$message"
        else
            echo "Timestamp: $timestamp"
            echo "IP Address: $ip"
            echo "Username: $user"
            echo "Message: $message"
            echo "---"
        fi
        
    done < "$temp_file"
    
    rm -f "$temp_file"
}

# Function to generate summary
generate_summary() {
    local temp_file=$(mktemp)
    
    # Collect all data
    for log_file in "${LOG_FILES[@]}"; do
        parse_log_file "$log_file" >> "$temp_file" 2>/dev/null || true
    done
    
    if [[ ! -s "$temp_file" ]]; then
        print_warning "No failed SSH attempts found in any log files"
        rm -f "$temp_file"
        return 0
    fi
    
    print_info "Generating summary..."
    
    # Count total attempts
    local total_attempts=$(wc -l < "$temp_file")
    
    # Count unique IPs
    local unique_ips=$(awk -F'|' '{print $2}' "$temp_file" | sort -u | wc -l)
    
    # Count unique users
    local unique_users=$(awk -F'|' '{print $3}' "$temp_file" | sort -u | wc -l)
    
    # Top attacking IPs
    echo "=== SSH FAILED ATTEMPTS SUMMARY ==="
    echo "Total failed attempts: $total_attempts"
    echo "Unique attacking IPs: $unique_ips"
    echo "Unique usernames targeted: $unique_users"
    echo ""
    
    echo "=== TOP 10 ATTACKING IP ADDRESSES ==="
    awk -F'|' '{print $2}' "$temp_file" | sort | uniq -c | sort -nr | head -10 | while read count ip; do
        echo "$count attempts from $ip"
    done
    echo ""
    
    echo "=== TOP 10 TARGETED USERNAMES ==="
    awk -F'|' '{print $3}' "$temp_file" | sort | uniq -c | sort -nr | head -10 | while read count user; do
        echo "$count attempts for user '$user'"
    done
    echo ""
    
    echo "=== RECENT ATTEMPTS (Last 10) ==="
    tail -10 "$temp_file" | while IFS='|' read -r timestamp ip user message; do
        echo "$timestamp - $ip tried to access '$user'"
    done
    
    rm -f "$temp_file"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--summary)
            SUMMARY_ONLY=true
            shift
            ;;
        -f|--from-date)
            FROM_DATE="$2"
            shift 2
            ;;
        -t|--to-date)
            TO_DATE="$2"
            shift 2
            ;;
        -w|--whitelist)
            IP_WHITELIST="$2"
            shift 2
            ;;
        -a|--auth-log)
            LOG_FILES+=("/var/log/auth.log")
            shift
            ;;
        -m|--messages)
            LOG_FILES+=("/var/log/messages")
            shift
            ;;
        -s|--secure)
            LOG_FILES+=("/var/log/secure")
            shift
            ;;
        -*)
            print_error "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            LOG_FILES+=("$1")
            shift
            ;;
    esac
done

# Check if we have any log files
if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
    # Default to auth.log if no files specified
    if [[ -f "/var/log/auth.log" ]]; then
        LOG_FILES+=("/var/log/auth.log")
        print_info "Using default log file: /var/log/auth.log"
    else
        print_error "No log files specified and no default auth.log found"
        usage
        exit 1
    fi
fi

# Validate whitelist file if specified
if [[ -n "$IP_WHITELIST" && ! -f "$IP_WHITELIST" ]]; then
    print_error "Whitelist file $IP_WHITELIST does not exist"
    exit 1
fi

# Main execution
main() {
    print_info "Starting SSH failed attempts parser..."
    print_info "Log files to process: ${LOG_FILES[*]}"
    
    if [[ -n "$FROM_DATE" ]]; then
        print_info "Filtering from date: $FROM_DATE"
    fi
    
    if [[ -n "$TO_DATE" ]]; then
        print_info "Filtering to date: $TO_DATE"
    fi
    
    if [[ -n "$IP_WHITELIST" ]]; then
        print_info "Using IP whitelist: $IP_WHITELIST"
    fi
    
    # Redirect output if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > "$OUTPUT_FILE"
        print_info "Output will be saved to: $OUTPUT_FILE"
    fi
    
    # Generate summary or detailed report
    if [[ "$SUMMARY_ONLY" == "true" ]]; then
        generate_summary
    else
        for log_file in "${LOG_FILES[@]}"; do
            parse_log_file "$log_file"
        done
    fi
    
    print_success "Parsing completed successfully"
}

# Run main function
main "$@"

# Check every hour
while true; do
    echo "=== $(date) ==="
    ./ssh_failed_attempts_parser.sh -s /var/log/auth.log
    echo "Sleeping for 1 hour..."
    sleep 3600
done

# Check last 24 hours
./ssh_failed_attempts_parser.sh -f "$(date -d '24 hours ago' +%Y-%m-%d)" -s /var/log/auth.log