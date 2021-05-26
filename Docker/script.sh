#!/bin/bash

if [ "$#" -ne 2 ]
then
    echo "[+] Usage: prepare-amiibo <uid> <amiibo.bin>"
    exit 1
fi

key1=locked-secret.bin
key2=unfixed-info.bin

if [ ! -f "$key1" ]; then
    echo "[>] Downloading $key1"
    wget -q https://github.com/Shvier/TagMoUnlockFiles/raw/master/locked-secret.bin
    echo "[*] Downloaded $key1"
fi

if [ ! -f "$key2" ]; then
    echo -e "\n[>] Downloading $key2"
    wget -q https://github.com/Shvier/TagMoUnlockFiles/raw/master/unfixed-info.bin
    echo "[*] Downloaded $key2"
fi

uid=$(echo $1 | sed -E 's/.{2}/& /g')
filename="${2%.*}"

echo -e "\n[>] Changing UID..."
amiibo uid $2 "$uid" $filename-new.bin
echo "[*] Done! Saved to $filename-new.bin"
