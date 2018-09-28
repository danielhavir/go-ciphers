#!/bin/bash

bold=$(tput bold)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
normal=$(tput sgr0)

#url="http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip"
#echo "${bold}Downloading${normal} $url"
#wget $url -o goaes/jsontests/KAT_AES.zip

if [ -e goaes/jsontests/KAT_AES.zip ] || [ -e goaes/jsontests/kat_aes.zip ]
then
    cd goaes/jsontests
    echo `pwd`

    # *.zip to account for both KAT_AES.zip and kat_aes.zip
    unzip *.zip
    echo "####"

    go build parse_rsp.go

    echo "Parsing .rsp files into .json files:"
    for rsp_file in *.rsp; do
        ./parse_rsp -in=$rsp_file
    done

    echo "####"
    echo "${green}Tests successfully downloaded and extracted${normal}"
    echo "Navigate to ${bold}/goaes${normal} and Run ${yellow}${bold}go test${normal}"
else
    echo "Please ${bold}download${normal} tests in a .zip file first from: ${yellow}http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip${normal}"
    echo "Also, make sure that the .zip file is in the right directory ${bold}/goaes/jsontests${normal}"
fi
