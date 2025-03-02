#!/bin/bash
# Luveedu Antivirus - /usr/local/bin/luvd-antivirus

# Default directory to scan
SCAN_DIR="/home"
SCAN_LOG="/var/log/luvd-antivirus.log"
LOG_DIR="/var/log/luvd-antivirus"
LOG_FILE="$LOG_DIR/clamav_scan_log_$(date +%Y%m%d_%H%M%S).txt"
QUARANTINE_DIR="/tmp/quarantine"
UPDATE_URL="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-antivirus.sh"
RKHUNTER_LOG="/var/log/rkhunter.log"
EXCLUDE_FOLDERS=("/opt" "/proc" "/cyberpanel" "/backup")

# Ensure log directories exist
[ ! -d "/var/log" ] && sudo mkdir -p "/var/log"
[ ! -f "$SCAN_LOG" ] && sudo touch "$SCAN_LOG" && sudo chmod 644 "$SCAN_LOG"
[ ! -d "$LOG_DIR" ] && sudo mkdir -p "$LOG_DIR" && sudo chmod 755 "$LOG_DIR"

# Setup quarantine directory in /tmp with restrictions
setup_quarantine() {
    if [ ! -d "$QUARANTINE_DIR" ]; then
        sudo mkdir -p "$QUARANTINE_DIR"
        sudo chown root:root "$QUARANTINE_DIR"
        sudo chmod 700 "$QUARANTINE_DIR"
        if ! mountpoint -q "$QUARANTINE_DIR"; then
            sudo mount -t tmpfs -o noexec,nosuid,nodev tmpfs "$QUARANTINE_DIR"
        fi
    fi
}

check_running_scan() {
    if [ -f "/tmp/luvd-antivirus.pid" ]; then
        scan_pid=$(cat "/tmp/luvd-antivirus.pid")
        if ps -p "$scan_pid" >/dev/null; then
            echo "Error: A scan (PID: $scan_pid) is already running. Use 'luvd-antivirus --stop-scan' to stop it first."
            exit 1
        else
            rm -f "/tmp/luvd-antivirus.pid"
        fi
    fi
}

# Function to check if ClamAV is installed
check_clamav() {
    if ! command -v clamscan >/dev/null 2>&1; then
        echo "Error: ClamAV is not installed. Please install it first."
        echo "On Debian/Ubuntu: sudo apt install clamav"
        echo "On RHEL/Fedora: sudo dnf install clamav"
        exit 1
    fi
}

# Function to check if rkhunter is installed
check_rkhunter() {
    if ! command -v rkhunter >/dev/null 2>&1; then
        echo "Error: rkhunter is not installed. Please install it first."
        echo "On Debian/Ubuntu: sudo apt install rkhunter"
        echo "On RHEL/Fedora: sudo dnf install rkhunter"
        exit 1
    fi
}

# Function to update ClamAV signatures
update_signatures() {
    check_clamav
    echo "Updating ClamAV virus signatures..."
    echo "[$(date)] Updating ClamAV signatures" | sudo tee -a "$SCAN_LOG" >/dev/null
    if ! sudo freshclam >/dev/null 2>&1; then
        echo "Warning: Failed to update signatures."
        echo "[$(date)] Failed to update ClamAV signatures" | sudo tee -a "$SCAN_LOG" >/dev/null
    else
        echo "ClamAV signatures updated successfully."
        echo "[$(date)] ClamAV signatures updated successfully" | sudo tee -a "$SCAN_LOG" >/dev/null
    fi
}

# Function to update rkhunter database
update_rkhunter() {
    check_rkhunter
    echo "Updating rkhunter database..."
    echo "[$(date)] Updating rkhunter database" | sudo tee -a "$SCAN_LOG" >/dev/null
    if ! sudo rkhunter --update >/dev/null 2>&1; then
        echo "Warning: Failed to update rkhunter database."
        echo "[$(date)] Failed to update rkhunter database" | sudo tee -a "$SCAN_LOG" >/dev/null
    else
        echo "rkhunter database updated successfully."
        echo "[$(date)] rkhunter database updated successfully" | sudo tee -a "$SCAN_LOG" >/dev/null
    fi
}

# Function to scan with ClamAV
scan_clamav() {
    local dir_to_scan="$1"
    check_running_scan
    check_clamav
    setup_quarantine

    echo "[$(date)] Scan started for $dir_to_scan" | sudo tee -a "$SCAN_LOG" >/dev/null

    (
        total_files=$(find "$dir_to_scan" -type f 2>/dev/null | wc -l)
        echo "[$(date)] Total files to scan: $total_files" | sudo tee -a "$SCAN_LOG" >/dev/null

        {
            echo "Scan started at $(date)"
            echo "----------------------------------------"
        } >"$LOG_FILE"

        # Build exclude options for clamscan
        exclude_options=""
        for folder in "${EXCLUDE_FOLDERS[@]}"; do
            exclude_options="$exclude_options --exclude-dir=$folder"
        done

        find "$dir_to_scan" -type f 2>/dev/null | while IFS= read -r file; do
            echo "[$(date)] Scanning: $file" | sudo tee -a "$SCAN_LOG" >/dev/null
        done

        # Run clamscan with exclude options
        clamscan -r --bell --move="$QUARANTINE_DIR" --log="$LOG_FILE" $exclude_options "$dir_to_scan" 2>/dev/null
        exit_code=$?

        infected=$(grep -c "FOUND" "$LOG_FILE")
        echo "[$(date)] Scan completed. Scanned: $total_files, Infected: $infected" | sudo tee -a "$SCAN_LOG" >/dev/null
        {
            if [ $exit_code -eq 0 ]; then
                echo "No viruses found"
            elif [ $exit_code -eq 1 ]; then
                echo "Viruses found and quarantined"
            else
                echo "Scan failed with error"
            fi
            echo "Scan completed at $(date)"
        } >>"$LOG_FILE"
    ) &
    scan_pid=$!
    echo "$scan_pid" >"/tmp/luvd-antivirus.pid"
    echo "Luveedu Antivirus Scan Powered by ClamAV Started! - Try, 'luvd-antivirus --check-logs' to get the Logs."
}

# Function to scan with rkhunter
scan_rkhunter() {
    check_running_scan
    check_rkhunter
    echo "[$(date)] Rootkit scan started" | sudo tee -a "$SCAN_LOG" >/dev/null
    (
        sudo rkhunter --check --skip-keypress --logfile "$RKHUNTER_LOG" >/dev/null 2>&1
        echo "[$(date)] Rootkit scan completed" | sudo tee -a "$SCAN_LOG" >/dev/null
    ) &
    scan_pid=$!
    echo "$scan_pid" >"/tmp/luvd-antivirus.pid"
    echo "Rootkit scan started in background (PID: $scan_pid). Check $RKHUNTER_LOG for details."
}

# Function to update script
update_script() {
    echo "Updating script from $UPDATE_URL..."
    if curl -s "$UPDATE_URL" -o "/tmp/luvd-antivirus.sh"; then
        sudo mv "/tmp/luvd-antivirus.sh" "/usr/local/bin/luvd-antivirus"
        sudo chmod +x "/usr/local/bin/luvd-antivirus"
        echo "[$(date)] Script updated successfully" | sudo tee -a "$SCAN_LOG" >/dev/null
        echo "Script updated successfully."

        if systemctl is-active clamav-freshclam >/dev/null 2>&1; then
            sudo systemctl restart clamav-freshclam
            echo "[$(date)] ClamAV service restarted" | sudo tee -a "$SCAN_LOG" >/dev/null
        fi
    else
        echo "Failed to update script."
        echo "[$(date)] Failed to update script" | sudo tee -a "$SCAN_LOG" >/dev/null
        exit 1
    fi
}

# Function to check logs with real-time progress (ClamAV)
check_logs() {
    if [ -f "$SCAN_LOG" ] && [ -f "/tmp/luvd-antivirus.pid" ]; then
        scan_pid=$(cat "/tmp/luvd-antivirus.pid")
        if ps -p "$scan_pid" >/dev/null; then
            while ps -p "$scan_pid" >/dev/null; do
                clear
                total_files=$(grep "Total files to scan" "$SCAN_LOG" | tail -n 1 | awk '{print $NF}')
                scanned_files=$(grep "Scanning:" "$SCAN_LOG" | wc -l)
                infected=$(grep -c "FOUND" "$LOG_FILE" 2>/dev/null || echo 0)

                echo "Luveedu Antivirus - Scanning Logs (Updates every 10 seconds)"
                echo "------------------------------------------------------------"
                printf "| %-17s | %-15s | %-15s |\n" "Total Files" "Scanned Files" "Infected Files"
                echo "------------------------------------------------------------"
                printf "| %-17s | %-15s | %-15s |\n" "$total_files" "$scanned_files" "$infected"
                echo "------------------------------------------------------------"

                if [ "$total_files" -gt 0 ]; then
                    percentage=$((scanned_files * 100 / total_files))
                    echo "Scanning $percentage% completed"
                    echo -n "["
                    for ((i = 0; i < percentage / 2; i++)); do echo -n "•"; done
                    for ((i = percentage / 2; i < 50; i++)); do echo -n " "; done
                    echo "]"
                fi
                sleep 10
            done
        else
            echo "Luveedu Antivirus - Scanning Logs (Updates every 10 seconds)"
            echo "------------------------------------------------------------"
            echo "No Manual Scan Running! Try luvd-antivirus --scan to scan the entire home directory"
            rm -f "/tmp/luvd-antivirus.pid"
        fi
    else
        echo "Luveedu Antivirus - Scanning Logs (Updates every 10 seconds)"
        echo "------------------------------------------------------------"
        echo "No Manual Scan Running! Try luvd-antivirus --scan to scan the entire home directory"
    fi
}

# Function to check rkhunter logs
check_rkhunter_logs() {
    if [ -f "$RKHUNTER_LOG" ]; then
        echo "Luveedu Antivirus - rkhunter Logs"
        echo "------------------------------------------------------------"
        cat "$RKHUNTER_LOG"
    else
        echo "Luveedu Antivirus - rkhunter Logs"
        echo "------------------------------------------------------------"
        echo "No rkhunter logs found! Try luvd-antivirus --scan --rootkit"
    fi
}

# Function to check stats (last 10 scans)
check_stats() {
    if [ -f "$SCAN_LOG" ] && grep -q "Scan completed" "$SCAN_LOG"; then
        echo "Luveedu Antivirus - Scan History (Last 10 Results)"
        echo "------------------------------------------------------------"
        printf "| %-19s | %-15s | %-15s |\n" "Date & Time" "Scanned Files" "Infected Files"
        echo "------------------------------------------------------------"
        grep "Scan completed" "$SCAN_LOG" | tail -n 10 | while IFS= read -r line; do
            date_time=$(echo "$line" | cut -d']' -f1 | cut -d'[' -f2)
            scanned=$(echo "$line" | awk '{print $5}' | tr -d ',')
            infected=$(echo "$line" | awk '{print $7}' | tr -d ',')
            printf "| %-19s | %-15s | %-15s |\n" "$date_time" "$scanned" "$infected"
        done
        echo "------------------------------------------------------------"
    else
        echo "Luveedu Antivirus - Scan History (Last 10 Results)"
        echo "------------------------------------------------------------"
        echo "No Results Found!"
    fi
}

# Function to stop scan
stop_scan() {
    if [ -f "/tmp/luvd-antivirus.pid" ]; then
        scan_pid=$(cat "/tmp/luvd-antivirus.pid")
        if ps -p "$scan_pid" >/dev/null; then
            sudo kill -9 "$scan_pid"
            rm -f "/tmp/luvd-antivirus.pid"
            echo "[$(date)] Scan (PID: $scan_pid) stopped forcefully" | sudo tee -a "$SCAN_LOG" >/dev/null
            echo "Scan stopped successfully."
        else
            echo "No running scan found."
            rm -f "/tmp/luvd-antivirus.pid"
        fi
    else
        echo "No active scan PID found."
    fi
}

# Function to list infected files
infected_files() {
    if [ -f "$LOG_FILE" ] && grep -q "FOUND" "$LOG_FILE"; then
        infected_count=$(grep -c "FOUND" "$LOG_FILE")
        echo "Luveedu Antivirus - Infected Files ($infected_count):"
        echo "--------------------------------"
        grep "FOUND" "$LOG_FILE" | awk '{print $1}' | while IFS= read -r file; do
            echo "$file"
        done
        echo "--------------------------------"
    else
        echo "No Infected Files Found!"
    fi
}

# Function to remove all from quarantine
remove_all() {
    setup_quarantine
    if [ -n "$(ls -A "$QUARANTINE_DIR")" ]; then
        sudo rm -rf "$QUARANTINE_DIR"/*
        echo "[$(date)] All files permanently removed from $QUARANTINE_DIR" | sudo tee -a "$SCAN_LOG" >/dev/null
        echo "All files permanently removed from quarantine."
    else
        echo "Quarantine directory is already empty."
    fi
}

# Function to restore a file from quarantine
restore_file() {
    local file_name="$1"
    if [ -z "$file_name" ]; then
        echo "Error: Please specify a file name to restore."
        exit 1
    fi

    setup_quarantine
    local quarantined_file="$QUARANTINE_DIR/$file_name"
    if [ -f "$quarantined_file" ]; then
        local original_path=$(grep "$file_name" "$LOG_FILE" | grep -o "FOUND.*$" | awk '{print $2}' | head -n 1)
        if [ -n "$original_path" ]; then
            sudo mv "$quarantined_file" "$original_path"
            echo "[$(date)] Restored $file_name to $original_path" | sudo tee -a "$SCAN_LOG" >/dev/null
            echo "File $file_name restored to $original_path."
        else
            echo "Could not determine original path for $file_name. Restoring to $SCAN_DIR."
            sudo mv "$quarantined_file" "$SCAN_DIR/"
            echo "[$(date)] Restored $file_name to $SCAN_DIR (original path unknown)" | sudo tee -a "$SCAN_LOG" >/dev/null
        fi
    else
        echo "File $file_name not found in $QUARANTINE_DIR."
        exit 1
    fi
}

# Function to clear logs
clear_logs() {
    if [ -d "$LOG_DIR" ] || [ -f "$SCAN_LOG" ]; then
        sudo rm -rf "$LOG_DIR"/* "$SCAN_LOG"
        sudo touch "$SCAN_LOG" && sudo chmod 644 "$SCAN_LOG"
        echo "[$(date)] All logs cleared" | sudo tee -a "$SCAN_LOG" >/dev/null
        echo "All logs cleared successfully."
    else
        echo "No logs to clear."
    fi
}

# Function to list and select domains
scan_domains() {
    domains=($(find "$SCAN_DIR" -maxdepth 1 -type d -name "*.*" -exec basename {} \;))
    if [ ${#domains[@]} -eq 0 ]; then
        echo "No domain folders found in $SCAN_DIR!"
        exit 1
    fi

    echo "Which domain you want to scan? Enter the number only!"
    for i in "${!domains[@]}"; do
        printf "%d. %s\n" "$((i + 1))" "${domains[$i]}"
    done
    echo -n "> "
    read choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#domains[@]}" ]; then
        domain_dir="$SCAN_DIR/${domains[$((choice - 1))]}"
        scan_clamav "$domain_dir"
    else
        echo "Invalid selection!"
        exit 1
    fi
}

# New function to start the service (runs periodic scans)
start_service() {
    check_clamav
    update_signatures
    echo "[$(date)] Luveedu Antivirus service started" | sudo tee -a "$SCAN_LOG" >/dev/null
    (
        while true; do
            scan_clamav "$SCAN_DIR"
            sleep 86400  # Run scan every day
        done
    ) &
    service_pid=$!
    echo "$service_pid" >"/var/run/luvd-antivirus.pid"
    echo "Luveedu Antivirus service started (PID: $service_pid). Scans will run hourly."
}

# New function to stop the service
stop_service() {
    if [ -f "/var/run/luvd-antivirus.pid" ]; then
        service_pid=$(cat "/var/run/luvd-antivirus.pid")
        if ps -p "$service_pid" >/dev/null; then
            sudo kill -9 "$service_pid"
            sudo killall -9 luvd-antivirus
            rm -f "/var/run/luvd-antivirus.pid"
            echo "[$(date)] Luveedu Antivirus service (PID: $service_pid) stopped" | sudo tee -a "$SCAN_LOG" >/dev/null
            echo "Luveedu Antivirus service stopped successfully."
        else
            echo "No running service found."
            rm -f "/var/run/luvd-antivirus.pid"
        fi
    else
        echo "No active service PID found."
    fi
}

# Parse command-line options
case "$1" in
--start)
    start_service
    ;;
--stop)
    stop_service
    ;;
--scan)
    shift
    case "$1" in
    "")
        scan_clamav "$SCAN_DIR"
        ;;
    --folder)
        if [ -z "$2" ] || [ ! -d "$2" ]; then
            echo "Error: Please specify a valid folder to scan."
            exit 1
        fi
        scan_clamav "$2"
        ;;
    --domains)
        scan_domains
        ;;
    --mail)
        scan_clamav "/home/vmail"
        ;;
    --rootkit)
        scan_rkhunter
        ;;
    *)
        echo "Usage: luvd-antivirus --scan [--folder <path> | --domains | --mail | --rootkit]"
        exit 1
        ;;
    esac
    ;;
--update)
    update_script
    ;;
--check-logs)
    shift
    case "$1" in
    --rkhunter)
        check_rkhunter_logs
        ;;
    *)
        check_logs
        ;;
    esac
    ;;
--check-stats)
    check_stats
    ;;
--stop-scan)
    stop_scan
    ;;
--infected-files)
    infected_files
    ;;
--refresh)
    shift
    case "$1" in
    --rkhunter)
        update_rkhunter
        ;;
    *)
        update_signatures
        ;;
    esac
    ;;
--remove-all)
    remove_all
    ;;
--restore)
    restore_file "$2"
    ;;
--clear-logs)
    clear_logs
    ;;
*)
    echo "Usage: luvd-antivirus [OPTION] [ARGUMENT]"
    echo "Options:"
    echo "  --start             Start the antivirus service (runs periodic scans)"
    echo "  --stop              Stop the antivirus service"
    echo "  --scan              Scan entire home directory"
    echo "  --scan --folder <path>  Scan a specific folder"
    echo "  --scan --domains    Select and scan a domain folder"
    echo "  --scan --mail       Scan /home/vmail"
    echo "  --scan --rootkit    Scan for rootkits with rkhunter"
    echo "  --update            Update the script from GitHub"
    echo "  --check-logs        Show ClamAV scan progress and stats"
    echo "  --check-logs --rkhunter Show rkhunter logs"
    echo "  --check-stats       Show last 10 scan results"
    echo "  --stop-scan         Stop all running scans"
    echo "  --infected-files    List infected files from last scan"
    echo "  --refresh           Update ClamAV signatures"
    echo "  --refresh --rkhunter Update rkhunter database"
    echo "  --remove-all        Permanently delete all files from Quarantine"
    echo "  --restore <file>    Restore a specific file from quarantine"
    echo "  --clear-logs        Clear all logs"
    exit 1
    ;;
esac