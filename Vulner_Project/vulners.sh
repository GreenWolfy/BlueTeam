#!/bin/bash


# Function to print the VULNERS banner
function print_banner() {
    echo " __   __  _   _   _      _  _   ___   ___   ___ "
    echo " \ \ / / | | | | | |    | \| | | __| | _ \ / __|"
    echo "  \ V /  | |_| | | |__  | .\` | | _|  |   / \__ \\"
    echo "   \_/    \___/  |____| |_|\_| |___| |_|_\\ |___/"
    echo "                                             "
    echo ""
}

# Print the VULNERS banner
print_banner

HOME=$(pwd)
LOCAL_IP=$(hostname -I | awk '{print $1}')
NET_RANGE=$(ipcalc $LOCAL_IP | grep Network: | awk '{print $2}')
num_found_devices=0

# Check if Scanner directory exists, if not, create it
if [ ! -d "$HOME_DIR/Scanner" ]; then
    mkdir -p "$HOME_DIR/Scanner"
    echo "Scanner directory created."
fi

# Check if Local IP directory exists, if not, create it
if [ ! -d "$HOME_DIR/Scanner/$LOCAL_IP" ]; then
    mkdir -p "$HOME_DIR/Scanner/$LOCAL_IP"
    echo "$LOCAL_IP directory created."
fi


function VULN() {
    echo ""
        HOSTS_IPS=$(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Up | sed 's/(/ /g; s/)/ /g' | awk '{print $2}')

    echo "[+] Looking for possible vulnerabilities:"
    for address in $HOSTS_IPS; do
        sudo nmap $address --script=vulners.nse -O -sV >> $HOME/Scanner/$LOCAL_IP/Vulns_$address.txt 
        if grep -q CVE "$HOME/Scanner/$LOCAL_IP/Vulns_$address.txt"; then
            echo "[!] Vulnerabilities were found for $address. File saved - $HOME/Scanner/$LOCAL_IP/Vulns_$address.txt."
        else
            echo "[-] No vulnerabilities were found for $address."
            echo ""
        fi
    done
}

function ENUM() {
    HOSTS_IPS=$(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Up | sed 's/(/ /g; s/)/ /g' | awk '{print $2}')
    $(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Host | grep open | sed 's/\//n/g' |  sed 's/   /\n/g' > $HOME/Scanner/$LOCAL_IP/Enum_$ip.txt)
    for ip in $HOSTS_IPS; do
        open_ports=$(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep open | awk '{print $3}')
        
        if [ -n "$open_ports" ]; then
            echo "[+] Found open ports for $ip: $open_ports"
            
            # Call VULN function only if there are open ports
 
        else
            echo "[-] No open ports found for $ip."
        fi
        
        if grep -q OS: "$HOME/Scanner/$LOCAL_IP/Vulns_$ip.txt"; then #Checks whether a word exists in a file.
            echo "OS found"
        else
            echo "[-] Couldn't recognize the OS being used by the device."
        fi
        echo ""
    done

 VULN
}


function BRUTEFORCE() {
	
    read -p "Provide full path to a username list:" userlist
    read -p "Provide full path to password list:" passlist
    

    read -p "Choose IP to bruteforce" host
	echo "Choose service to bruteforce" 
	echo "Available options: ssh, http, ftp , telnet"
	read -p "" chosen_service

        # Brute force with the chosen service using Medusa
        case $chosen_service in
            ssh)
                medusa -h $host -U $userlist -P $passlist -M ssh -O $HOME_DIR/Scanner/$LOCAL_IP/hydra.txt
                ;;
            http|https)
                medusa -h $host -U $userlist -P $passlist -M http -O $HOME_DIR/Scanner/$LOCAL_IP/hydra.txt
                ;;
            ftp)
                medusa -h $host -U $userlist -P $passlist -M ftp -O $HOME_DIR/Scanner/$LOCAL_IP/hydra.txt
                ;;
            telnet)
                medusa -h $host -U $userlist -P $passlist -M telnet -O $HOME_DIR/Scanner/$LOCAL_IP/hydra.txt
                ;;
            *)
                echo "No supported login service found."
                ;;
        esac
     
}

function START() {
    mkdir -p $HOME/Scanner/$LOCAL_IP
    echo "[+] Local IP address: $LOCAL_IP"
    echo "[+] Net range: $NET_RANGE"

    scan_start_time=$(date +%Y-%m-%d_%H-%M-%S)

    echo "[+] Scanning the LAN..."
    sudo nmap $NET_RANGE -p- -O -oG $HOME/Scanner/$LOCAL_IP/Scan.txt  > /dev/null 2>&1
    echo "[+] Total hosts (UP): $(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Up | sed 's/(/ /g; s/)/ /g' | wc -l)"
    cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Up | sed 's/(/ /g; s/)/ /g'
    echo ""
    ENUM

    scan_end_time=$(date +%Y-%m-%d_%H-%M-%S)
    num_found_devices=$(cat $HOME/Scanner/$LOCAL_IP/Scan.txt | grep Up | sed 's/(/ /g; s/)/ /g' | wc -l)
}

function LISTS() {
    echo "Do you want to create your own passlist? (y/n)"
    read answer
    if [ "$answer" = "n" ]; then
        BRUTEFORCE
    elif [ "$answer" = "y" ]; then
        echo "Enter passwords one by one and press Enter. Type 'done' when finished."
        touch $HOME/Scanner/$LOCAL_IP/passlist.txt
        while true; do
            read password
            if [ "$password" = "done" ]; then
                echo "The password list was saved in - $HOME/Scanner/$LOCAL_IP/passlist.txt"
                BRUTEFORCE
                break
            else
                echo "$password" >> $HOME/Scanner/$LOCAL_IP/passlist.txt
            fi
        done
    else
        echo "Invalid input. Please enter 'y' or 'n'."
        LISTS
    fi
}



function DISPLAY_STATISTICS() {
    echo "Scan Start Time: $scan_start_time"
    echo "Scan End Time: $scan_end_time"
    echo "Number of Found Devices: $num_found_devices"
}

function SAVE_REPORT() {
    report_file="$HOME/Scanner/$LOCAL_IP/Scan_Report.txt"
    echo "Scan Start Time: $scan_start_time" > "$report_file"
    echo "Scan End Time: $scan_end_time" >> "$report_file"
    echo "Number of Found Devices: $num_found_devices" >> "$report_file"
    # ... (Other relevant information you want to save)

    echo "Results have been saved to: $report_file"
}

function SEARCH_IP() {
    read -p "Enter an IP address to search for: " search_ip
    if grep -q "$search_ip" "$HOME/Scanner/$LOCAL_IP/Scan.txt"; then
        echo "IP address $search_ip found in the scan results."
        # Display other relevant information about the IP address
    else
        echo "IP address $search_ip not found in the scan results."
    fi
}


function MENU {
PS3="Select an action: "
select action in "Start Scan" "Create Lists" "Run All" "Run medusa" "Display Statistics" "Save Report" "Search IP" "Quit"; do
    case $action in
        "Start Scan")
            START
            ;;
        "Create Lists")
            LISTS
            ;;
        "Run All")
            START
            LISTS
            BRUTEFORCE
            ;;
            "Run medusa")
            BRUTEFORCE
            ;;
        "Display Statistics")
            DISPLAY_STATISTICS
            ;;
        "Save Report")
            SAVE_REPORT
            ;;
        "Search IP")
            SEARCH_IP
            ;;
        "Quit")
            echo "Exiting..."
            exit
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
done
}

MENU
