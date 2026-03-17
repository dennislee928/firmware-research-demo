#!/bin/bash

# Configuration
# Use absolute paths for cron reliability
PROJECT_DIR="/Users/dennis_leedennis_lee/Documents/GitHub/firmware-research-demo"
RULES_DIR="$PROJECT_DIR/yara-rules"
TEMP_DIR="/tmp/yara_update"

mkdir -p "$RULES_DIR"
mkdir -p "$TEMP_DIR"

echo "Updating YARA rules in $RULES_DIR..."

# List of official/authoritative rule URLs (Bash 3.2 compatible)
# Format: "filename|url"
RULES=(
    "APT_Equation|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Equation.yar"
    "spy_equation_fiveeyes|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/spy_equation_fiveeyes.yar"
    "apt_vpnfilter|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_vpnfilter.yar"
    "apt_blackenergy|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_blackenergy.yar"
    "apt_fancybear_dnc|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_fancybear_dnc.yar"
    "apt_waterbear|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_waterbear.yar"
    "apt_plead_downloader|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_plead_downloader.yar"
    "gen_tscookie_rat|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_tscookie_rat.yar"
    "apt_venom_linux_rootkit|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_venom_linux_rootkit.yar"
    "Windows_Trojan_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Generic.yar"
    "Linux_Trojan_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Generic.yar"
    "Windows_Trojan_Trickbot|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Trickbot.yar"
    "Linux_Trojan_Mirai|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Mirai.yar"
)

for rule in "${RULES[@]}"; do
    filename_base="${rule%%|*}"
    url="${rule#*|}"
    filename="${filename_base}.yar"
    
    echo "Downloading $filename..."
    curl -sL "$url" -o "$TEMP_DIR/$filename"
    
    # Check if file exists and is larger than 100 bytes (to avoid 404 pages)
    if [ -f "$TEMP_DIR/$filename" ]; then
        # Handle different 'stat' versions (BSD vs GNU)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            size=$(stat -f%z "$TEMP_DIR/$filename")
        else
            size=$(stat -c%s "$TEMP_DIR/$filename")
        fi

        if [ "$size" -gt 100 ]; then
            mv "$TEMP_DIR/$filename" "$RULES_DIR/$filename"
            echo "Successfully updated $filename"
        else
            echo "Skipped $filename (too small, likely 404)"
            rm -f "$TEMP_DIR/$filename"
        fi
    else
        echo "Failed to download $filename"
    fi
done

rm -rf "$TEMP_DIR"
echo "YARA rules update complete."
