#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${RESET}"
    exit 1
fi

# Check if Docker Scout is installed
if ! docker scout --help &> /dev/null; then
    echo -e "${RED}Docker Scout is not installed. Please install Docker Scout first.${RESET}"
    exit 1
fi

# Header Art for the script
echo -e "${GREEN}${BOLD}-----------------------------"
echo -e "${BLUE}${BOLD} Docker Image Vulnerability Scan"
echo -e "${GREEN}${BOLD}-----------------------------${RESET}"

# List all available Docker images with index
echo -e "\n${YELLOW}${BOLD}Select an image:${RESET}"
images=$(docker images --format "{{.Repository}}:{{.Tag}}" )
i=1
declare -A images_array

# Loop through images and assign numbers
for image in $images; do
  echo -e "${GREEN}$i.${RESET} $image"
  images_array[$i]=$image
  ((i++))
done

# Ask the user to select image numbers
echo -e "\n${YELLOW}Enter the numbers of the images you want to scan (separate multiple numbers with space):${RESET}"
read -p "> " selected_numbers

# Check if the user entered anything
if [ -z "$selected_numbers" ]; then
  echo -e "${RED}No images selected. Exiting...${RESET}"
  exit 1
fi

# Loop through the selected image numbers and scan them
for num in $selected_numbers; do
  if [[ -v images_array[$num] ]]; then
    image="${images_array[$num]}"
    echo -e "\n${YELLOW}${BOLD}Scanning Image: ${UNDERLINE}$image${RESET}"
    
    echo -e "${BLUE}=========================================${RESET}"
    
    # Run Docker Scout for CVE vulnerabilities
    docker scout cves $image
    
    echo -e "${BLUE}=========================================${RESET}"
  else
    echo -e "${RED}Invalid selection: $num. Skipping...${RESET}"
  fi
done

echo -e "\n${GREEN}${BOLD}Scan complete! Review vulnerabilities for each selected image.${RESET}"
