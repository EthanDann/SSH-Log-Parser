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

# Associative array for whitelist
declare -A WHITELIST_IPS

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

DEPENDENCIES:
    - bash, grep, awk, sed, date
    - Optional: geoiplookup (for GeoIP in summary)
    - Note: Non-GNU systems (e.g., BSD/macOS) require compatible date command

TESTING:
    - Use a testing framework like bats or create sample logs to verify parsing
    - Example: echo "Jan 1 12:00:00 server sshd: Failed password for root from 192.168.1.1" > test.log

EXAMPLES:
    $0 /var/log/auth.log
    $0 -o failed_ssh.txt /var/log/auth.log /var/log/secure
    $0 -f "2024-01-01" -t "2024-01-31" /var/log/auth.log
    $0 -v -w whitelist.txt /var/log/auth.log
    # Run every hour:
    # while true; do
    #     echo "=== \$(date) ==="
    #     $0 -s /var/log/auth.log
    #     echo "Sleeping for 1 hour..."
    #     sleep 3600
    # done
    # Check last 24 hours:
    # $0 -f "\$(date -d '24 hours ago' +%Y-%m-%d)" -s /var/log/auth.log

NOTES:
    - Supports IPv4 and IPv6 addresses
    - Handles rotated logs (.1, .gz)
    - Custom log formats may require manual regex adjustments
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
        date_str="${date_str} 00:00:00"
    fi
    if date -d "$date_str" +%s 2>/dev/null; then
        date -d "$date_str" +%s
    elif date -j -f "%Y-%m-%d %H:%M:%S" "$date_str" +%s 2>/dev/null; then
        date -j -f "%Y-%m-%d %H:%M:%S" "$date_str" +%s
    else
        print_warning "Invalid date format: $date_str"
        echo "0"
    fi
}

# Function to check if IP is whitelisted
is_whitelisted() {
    local ip="$1"
    [[ -n "$IP_WHITELIST" && -n "${WHITELIST_IPS[$ip]}" ]]
}

# Function to parse log file
parse_log_file() {
    local log_file="$1"
    local temp_file=$(mktemp)

    print_info "Parsing $log_file..."

    # Check file existence and readability
    [[ ! -f "$log_file" ]] && { print_error "Log file $log_file does not exist"; return 1; }
    [[ ! -r "$log_file" ]] && { print_error "Log file $log_file is not readable"; return 1; }

    # Extract failed SSH attempts
    grep -E "(Failed password|Invalid user|Connection closed by invalid user|PAM authentication failure|Failed keyboard-interactive)" "$log_file" > "$temp_file" 2>/dev/null || true

    [[ ! -s "$temp_file" ]] && { print_warning "No failed SSH attempts found in $log_file"; rm -f "$temp_file"; return 0; }

    # Process with awk for efficiency
    awk -v verbose="$VERBOSE" -v from_date="$FROM_DATE" -v to_date="$TO_DATE" '
    function date_to_timestamp(date) {
        cmd = "date -d \"" date "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%d %H:%M:%S\" \"" date "\" +%s 2>/dev/null"
        cmd | getline ts
        close(cmd)
        return ts ? ts : 0
    }
    {
        # Extract timestamp
        if ($0 ~ /^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}/) {
            timestamp = $1 " " $2 " " $3
        } else if ($0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}/) {
            timestamp = $1
        } else if ($0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}/) {
            timestamp = $1 " " $2
        } else {
            next
        }

        # Extract IP (IPv4 and IPv6)
        ip = ""
        for (i=1; i<=NF; i++) {
            if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $i ~ /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/ || $i ~ /^([0-9a-fA-F]{1,4}:){0,7}:[0-9a-fA-F]{1,4}$/) {
                ip = $i
                break
            }
        }

        # Extract user
        user = ""
        if ($0 ~ /Failed password for/) {
            for (i=1; i<=NF; i++) {
                if ($i == "for" && i+1 <= NF) {
                    user = $(i+1)
                    break
                }
            }
        } else if ($0 ~ /Invalid user/) {
            for (i=1; i<=NF; i++) {
                if ($i == "user" && i+1 <= NF) {
                    user = $(i+1)
                    break
                }
            }
        }

        # Apply date filters
        if (from_date || to_date) {
            ts = date_to_timestamp(timestamp)
            if (from_date && ts < date_to_timestamp(from_date)) next
            if (to_date && ts > date_to_timestamp(to_date)) next
        }

        # Output
        if (verbose == "true") print "[DEBUG] Processing: " $0
        print timestamp "|" ip "|" user "|" $0
    }' "$temp_file" | while IFS='|' read -r timestamp ip user message; do
        # Skip whitelisted IPs
        is_whitelisted "$ip" && continue

        if [[ "$SUMMARY_ONLY" == "true" ]]; then
            echo "$timestamp|$ip|$user|$message"
        else
            echo "Timestamp: $timestamp"
            echo "IP Address: $ip"
            echo "Username: $user"
            echo "Message: $message"
            echo "---"
        fi
    done

    rm -f "$temp_file"
}

# Function to generate summary
generate_summary() {
    local temp_file=$(mktemp)

    # Collect all data
    for log_file in "${LOG_FILES[@]}"; do
        parse_log_file "$log_file" >> "$temp_file" 2>/dev/null || true
        # Handle rotated logs
        [[ -f "${log_file}.1" ]] && parse_log_file "${log_file}.1" >> "$temp_file" 2>/dev/null || true
        [[ -f "${log_file}.gz" ]] && zcat "${log_file}.gz" | grep -E "(Failed password|Invalid user|Connection closed by invalid user|PAM authentication failure|Failed keyboard-interactive)" | parse_log_file /dev/stdin >> "$temp_file" 2>/dev/null || true
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

    # Summary output
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

    # GeoIP lookup if available
    if command -v geoiplookup >/dev/null; then
        echo "=== TOP 10 ATTACKING IP COUNTRIES ==="
        awk -F'|' '{print $2}' "$temp_file" | sort | uniq -c | sort -nr | head -10 | while read count ip; do
            country=$(geoiplookup "$ip" | awk -F': ' '{print $2}' | head -1)
            echo "$count attempts from $ip ($country)"
        done
        echo ""
    fi

    echo "=== TOP 10 TARGETED USERNAMES ==="
    awk -F'|' '{print $3}' "$temp_file" | sort | uniq -c | sort -nr | head -10 | while read count user; do
        echo "$count attempts for user '$user'"
    done
    echo ""

    echo "=== RECENT ATTEMPTS (Last 10) ==="
    tail -10 "$temp_file" | while IFS='|' read -r timestamp ip user message; do
        echo "$timestamp - $ip tried to access '$user'"
    done

    [[ "$VERBOSE" == "true" ]] && print_info "Summary generated from $total_attempts entries"

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
    if [[ -f "/var/log/auth.log" ]]; then
        LOG_FILES+=("/var/log/auth.log")
        print_info "Using default log file: /var/log/auth.log"
    else
        print_error "No log files specified and no default auth.log found"
        usage
        exit 1
    fi
fi

# Validate and load whitelist
if [[ -n "$IP_WHITELIST" ]]; then
    if [[ ! -f "$IP_WHITELIST" ]]; then
        print_error "Whitelist file $IP_WHITELIST does not exist"
        exit 1
    fi
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && WHITELIST_IPS["$ip"]=1
    done < "$IP_WHITELIST"
    print_info "Loaded ${#WHITELIST_IPS[@]} IPs from whitelist"
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
            [[ -f "${log_file}.1" ]] && parse_log_file "${log_file}.1"
            [[ -f "${log_file}.gz" ]] && zcat "${log_file}.gz" | parse_log_file /dev/stdin
        done
    fi

    print_success "Parsing completed successfully"
}

# Run main function
main "$@"