#!/usr/bin/env bash

# Set the Packwiz modpack directory
packwiz_dir="../Packwiz"

# Function to display the script's introduction
show_intro() {
    clear
    echo -e "\e[32m"
    echo "  _     _  __      __  __  ____   ____  _             _ _           "
    echo " | |   (_)/ _| ___|  \/  |/ ___| / ___|| |_ _   _  __| (_) ___  ___ "
    echo " | |   | | |_ / _ \ |\/| | |     \___ \| __| | | |/ _\` | |/ _ \/ __|"
    echo " | |___| |  _|  __/ |  | | |___   ___) | |_| |_| | (_| | | (_) \__ \\"
    echo " |_____|_|_|  \___|_|  |_|\____| |____/ \__|\__,_|\__,_|_|\___/|___/"
    echo -e "\e[0m"
    
    echo -e "\e[33m"
    echo "This script was created by LifeMC Studios for internal use in our project."
    echo "It is open-source and intended to simplify specific operations within our team."
    echo "You can use it within our project without restrictions."
    echo ""
    echo "> All rights reserved. © 2021-2024 LifeMC Studios."
    echo -e "\e[0m"
}

# Function to display a loading animation
loading_animation() {
    local pid=$1
    local delay=0.1
    local spin[0]="-"
    local spin[1]="/"
    local spin[2]="|"
    local spin[3]="\\"
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        for i in "${spin[@]}"; do
            echo -ne "\e[33m[$i] \e[0mWorking... Please wait.\r"
            sleep $delay
        done
    done
    echo -e "\e[33m[Done] \e[0mOperation completed.          "
    sleep 1
}

# Function to display the version selection menu
show_menu() {
    echo -e "\e[34m"
    echo "Which version do you want to export?"
    echo "1. 1.18.2"
    echo "2. 1.19.4"
    echo "5. 1.20.4"
    echo "6. 1.20.5"
    echo "7. All versions"
    echo "8. Close"
    echo -e "\e[0m"
}

# Function to export the modpack for the selected version
export_modpack() {
    local selected_version="$1"
    echo -e "\e[32m"
    echo "You have selected $selected_version"
    echo -e "\e[0m"
    sleep 1
    cd "$packwiz_dir/$selected_version"
    
    # Export the modpack
    pw mr export &
    loading_animation $!
    mv *.mrpack ..
    cd -
    echo -e "\e[32m"
    echo "Modpack export completed!"
    echo -e "\e[0m"
    sleep 1
}

# Main script loop
while true; do
    show_intro
    show_menu
    read -p "Enter version (1-5): " choice
    
    case "$choice" in
        1)
            export_modpack "1.18.2"
        ;;
        2)
            export_modpack "1.19.4"
        ;;
        5)
            export_modpack "1.20.4"
        ;;
        6)
            export_modpack "1.20.5"
        ;;
        7)
            echo -e "\e[32m"
            echo "You have selected All versions"
            echo -e "\e[0m"
            sleep 1
            export_modpack "1.18.2"
            export_modpack "1.19.4"
            export_modpack "1.20.4"
            export_modpack "1.20.5"
        ;;
        8)
            echo -e "\e[31m"
            echo "Closure..."
            echo -e "\e[0m"
            sleep 1
            exit 0
        ;;
        *)
            echo -e "\e[31m"
            echo "Invalid choice. Enter a number between 1 and 5."
            echo -e "\e[0m"
            sleep 1
        ;;
    esac
    
    echo
done

# > All rights reserved. © 2021-2024 LifeMC Studios
