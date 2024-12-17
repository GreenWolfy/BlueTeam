#!/bin/bash

HOME=$(pwd)
TOOL=$HOME/res_file
#using TIME to prevent same name files creating a problem in the script
TIME=$(date +%s)

#Function checking if the script is run with root priviliges
#if not then the script closes and asks the user to run it again with sudo command or as root user
function ROOT() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        exit
    else
        START
    fi
}

#Start function that asks the user to provide full path to the file he wants to run the forensics this function calls install
#forensics tools
function START() {
    echo "[+] Enter a full path to the memory file:"
    read file
    NAME=$(basename "$file")
    mkdir -p "$TOOL"
    mkdir -p "$TOOL/$NAME" > /dev/null 2>&1
    INSTALL_FORENSICS_TOOLS
}


function ANALYSIS() {
    echo "[+] Analyzing file $NAME"
    cd $TOOL
    mkdir "$TOOL/$NAME/vol_$TIME"
    # Gets the profile:
    PROFILE=$("./vol" -f "$file" imageinfo | grep Suggested | grep Win | awk -F '.' '{print $1}' | awk -F ':' '{print $2}' | sed 's/ //g')
    echo ""
    echo "[+] Investigated system profile: $PROFILE"
    PLUGINS="pstree connscan pslist hivelist printkey"
    echo "[+] Extracting information..."
    # Loop over the list of plugins
    for p in $PLUGINS; do
        echo "- Plugin being used: $p"
         ./vol -f "$NAME" --profile="$PROFILE" "$p" > "$TOOL/$NAME/res_$p.txt" 2> /dev/null
    done
    CARVERS
}

function ZIP() {
    cd $TOOL
    zip -r $NAME_results_$TIME.zip $NAME > /dev/null
    echo "[+] All results have been zipped into $NAME_results_$TIME.zip"
}


function INSTALL_FORENSICS_TOOLS() {
    # Checking if Foremost is installed
    if ! which foremost &>/dev/null; then
        echo ""
        echo "Foremost not found. Installing..."
        sudo apt install foremost
    else
        echo ""
        echo "Foremost is already installed."
    fi

    if ! which binwalk &>/dev/null; then
        echo ""
        echo "Binwalk not found. Installing..."
        sudo apt install binwalk
    else
        echo ""
        echo "Binwalk is installed."
    fi

    if ! which bulk_extractor &>/dev/null; then
        echo ""
        echo "Bulk_extractor not found. Installing..."
        sudo apt install bulk-extractor
    else
        echo ""
        echo "Bulk_extractor is installed."
    fi

    # Check if volatility is installed using -f because "which" command cannot find volatility is installed.
    if [[ ! -f "$TOOL/vol" ]]; then
        echo "Volatility not found. Installing..."
        echo "" 
        git clone https://github.com/volatilityfoundation/volatility.git
    else
        echo "Volatility is installed. Continuing..."
        echo "" 
        CHECK_FILE_TYPE
    fi
}

function CHECK_FILE_TYPE() {
    if [[ "${file##*.}" == "dd" ]]; then
        CARVERS
    elif [[ "${file##*.}" == "mem" ]]; then
        ANALYSIS
    else
        echo "Unsupported file type. Please provide a .dd or .mem file."
        exit 1
    fi
}

function CARVERS() {
    if [ ! -d "$TOOL/$NAME/foremost" ]; then
        mkdir "$TOOL/$NAME/foremost"
        echo ""
        echo "Carving with foremost"
        foremost -TQ "$file" -o "$TOOL/$NAME/foremost/Res_$TIME"
        echo "" 
    else
		echo ""
        echo "Carving with foremost"
        foremost -TQ "$file" -o "$TOOL/$NAME/foremost/Res_$TIME"
        echo "" 
    fi

    if [ ! -d "$TOOL/$NAME/bulk_extractor" ]; then
        mkdir "$TOOL/$NAME/bulk_extractor"
        echo "Carving with bulk_extractor"
        bulk_extractor "$file" -o "$TOOL/$NAME/bulk_extractor/res_$TIME"  > /dev/null
        echo "" 
    else
        echo "Carving with bulk_extractor"
        bulk_extractor "$file" -o "$TOOL/$NAME/bulk_extractor/res_$TIME"  > /dev/null
        echo "" 
    fi

     if [ ! -d "$TOOL/$NAME/strings" ]; then
        mkdir "$TOOL/$NAME/strings"
        echo "Carving with strings"
        strings "$file" >> "$TOOL/$NAME/strings/strings_$TIME"
        echo "" 
    else
        echo "Carving with strings"
        strings "$file" >> "$TOOL/$NAME/strings/strings_$TIME"
		fi
		echo "" 
		
		echo "[+] Done - results were saved"
		ZIP
}

ROOT
